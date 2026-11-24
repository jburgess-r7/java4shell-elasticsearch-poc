package org.elasticsearch.painless;

import java.io.Closeable;
import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Bridge loaded by the request-supplied class after the Painless chain succeeds.
 * The caller owns the anonymous library channel; this class verifies its inode
 * and contents, loads JNI once, and delegates command supervision to native code.
 * Closing that channel does not unload the JNI library or undo class definition.
 */
public final class OwnedNativeCommand {
    /* The generated request class writes the bridge into an anonymous inode
       and passes its channel here. Keeping that descriptor open avoids a
       shared pathname that another same-UID process could replace. */
    private static final String BUILD_ID = "__BRIDGE_BUILD_ID__";
    public static String buildId() { return BUILD_ID; }
    private static final int MAX_LIBRARY = 16 * 1024 * 1024;
    private static final int O_PATH_CLOEXEC = 0x280000;
    private static final int O_RDONLY_NONBLOCK_CLOEXEC = 0x80800;
    private static final int O_TMPFILE_EXCL_RDWR_CLOEXEC = 0x490082;
    private static final Object LOAD_LOCK = new Object();
    private static final Map<SeekableByteChannel, long[]> OWNED = new WeakHashMap<>();
    private static final MethodHandle OPEN, CLOSE, FD_SET, FD_CLOSE, CHANNEL_OPEN;
    private static final MethodHandle CHANNEL_FD, FD_NUMBER, FSTAT, STAT_DEV, STAT_INO;
    private static final MethodHandle STAT_MODE, STAT_NLINK, STAT_SIZE, STAT_MTIME, STAT_CTIME;
    private static final MethodHandle LOADER_LIBRARIES, LOAD_LIBRARY;
    private static final Class<?> CHANNEL_CLASS;
    private static byte[] loadedHash;
    private static boolean loadAttempted;
    private static native byte[][] invoke0(byte[][] argv, int timeoutSeconds);
    private static native void installFilterForTest0();

    static {
        try {
            int feature = Runtime.version().feature();
            if (!System.getProperty("os.name").equals("Linux")
                || !(System.getProperty("os.arch").equals("amd64")
                     || System.getProperty("os.arch").equals("x86_64"))
                || (feature != 17 && feature != 21))
                throw new UnsupportedOperationException("Anonymous loading requires the supported Linux x86-64 Java 17/21 runtimes");
            /* These pinned JDKs expose no public API for O_TMPFILE or for the
               literal-name JNI registry. Resolve their internal descriptor
               and loader operations once, using the lookup available after
               the Painless chain has reached this supplied class. */
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field singleton = unsafeClass.getDeclaredField("theUnsafe");
            singleton.setAccessible(true);
            Object unsafe = singleton.get(null);
            Field lookupField = MethodHandles.Lookup.class.getDeclaredField("IMPL_LOOKUP");
            Object base = unsafeClass.getMethod("staticFieldBase", Field.class).invoke(unsafe, lookupField);
            long offset = (Long)unsafeClass.getMethod("staticFieldOffset", Field.class).invoke(unsafe, lookupField);
            MethodHandles.Lookup lookup = (MethodHandles.Lookup)unsafeClass
                .getMethod("getObject", Object.class, long.class).invoke(unsafe, base, offset);
            Class<?> unixPath = Class.forName("sun.nio.fs.UnixPath");
            Class<?> dispatcher = Class.forName("sun.nio.fs.UnixNativeDispatcher");
            Class<?> attributes = Class.forName("sun.nio.fs.UnixFileAttributes");
            CHANNEL_CLASS = Class.forName("sun.nio.ch.FileChannelImpl");
            Class<?> libraries = Class.forName("jdk.internal.loader.NativeLibraries");
            Class<?> library = Class.forName("jdk.internal.loader.NativeLibrary");
            OPEN = lookup.findStatic(dispatcher, "open", MethodType.methodType(int.class, unixPath, int.class, int.class));
            CLOSE = lookup.findStatic(dispatcher, "close", MethodType.methodType(void.class, int.class));
            FD_SET = lookup.findVirtual(FileDescriptor.class, "set", MethodType.methodType(void.class, int.class));
            FD_CLOSE = lookup.findVirtual(FileDescriptor.class, "close", MethodType.methodType(void.class));
            CHANNEL_OPEN = lookup.findStatic(CHANNEL_CLASS, "open", MethodType.methodType(FileChannel.class,
                FileDescriptor.class, String.class, boolean.class, boolean.class, boolean.class,
                feature == 21 ? Closeable.class : Object.class));
            CHANNEL_FD = lookup.findGetter(CHANNEL_CLASS, "fd", FileDescriptor.class);
            FD_NUMBER = lookup.findGetter(FileDescriptor.class, "fd", int.class);
            FSTAT = lookup.findStatic(attributes, "get", MethodType.methodType(attributes, int.class));
            STAT_DEV = lookup.findVirtual(attributes, "dev", MethodType.methodType(long.class));
            STAT_INO = lookup.findVirtual(attributes, "ino", MethodType.methodType(long.class));
            STAT_MODE = lookup.findVirtual(attributes, "mode", MethodType.methodType(int.class));
            STAT_NLINK = lookup.findVirtual(attributes, "nlink", MethodType.methodType(int.class));
            STAT_SIZE = lookup.findVirtual(attributes, "size", MethodType.methodType(long.class));
            STAT_MTIME = lookup.findVirtual(attributes, "lastModifiedTime", MethodType.methodType(FileTime.class));
            STAT_CTIME = lookup.findVirtual(attributes, "ctime", MethodType.methodType(FileTime.class));
            LOADER_LIBRARIES = lookup.findGetter(ClassLoader.class, "libraries", libraries);
            LOAD_LIBRARY = lookup.findVirtual(libraries, "loadLibrary",
                MethodType.methodType(library, Class.class, String.class, boolean.class));
        } catch (Throwable failure) {
            throw new ExceptionInInitializerError(failure);
        }
    }

    private static IOException io(String message, Throwable failure) {
        if (failure instanceof IOException) return (IOException)failure;
        if (failure instanceof RuntimeException) throw (RuntimeException)failure;
        if (failure instanceof Error) throw (Error)failure;
        return new IOException(message, failure);
    }

    private static int open(Path path, int flags, int mode) throws IOException {
        try { return (int)OPEN.invoke(path, flags, mode); }
        catch (Throwable failure) { throw io("Opening " + path + " failed", failure); }
    }

    private static void closeRaw(int fd) throws IOException {
        try { CLOSE.invoke(fd); }
        catch (Throwable failure) { throw io("Closing descriptor failed", failure); }
    }

    private static long[] stat(int fd) throws IOException {
        try {
            Object a = FSTAT.invoke(fd);
            return new long[] {(long)STAT_DEV.invoke(a), (long)STAT_INO.invoke(a),
                (int)STAT_MODE.invoke(a), (int)STAT_NLINK.invoke(a), (long)STAT_SIZE.invoke(a),
                ((FileTime)STAT_MTIME.invoke(a)).to(TimeUnit.NANOSECONDS),
                ((FileTime)STAT_CTIME.invoke(a)).to(TimeUnit.NANOSECONDS)};
        } catch (Throwable failure) { throw io("Reading descriptor identity failed", failure); }
    }

    private static boolean regular(long[] a) { return (a[2] & 0170000) == 0100000; }
    private static boolean sameFile(long[] a, long[] b) {
        return regular(a) && regular(b) && a[0] == b[0] && a[1] == b[1];
    }

    /* Ownership passes to FileDescriptor before a channel is constructed. Its close
       invalidates the number, including a partly constructed channel's cleaner. */
    private static FileChannel channel(int raw, boolean writable) throws IOException {
        FileDescriptor descriptor = null;
        boolean attached = false;
        try {
            descriptor = new FileDescriptor();
            FD_SET.invoke(descriptor, raw);
            attached = true;
            return (FileChannel)CHANNEL_OPEN.invoke(descriptor, null, true, writable, false, null);
        } catch (Throwable failure) {
            try {
                if (attached) FD_CLOSE.invoke(descriptor);
                else CLOSE.invoke(raw);
            } catch (Throwable closing) { failure.addSuppressed(closing); }
            throw io("Constructing descriptor channel failed", failure);
        }
    }

    private static int descriptor(SeekableByteChannel channel) throws IOException {
        if (channel == null || channel.getClass() != CHANNEL_CLASS || !channel.isOpen())
            throw new IOException("Expected an open anonymous channel from this bridge");
        try { return (int)FD_NUMBER.invoke((FileDescriptor)CHANNEL_FD.invoke(channel)); }
        catch (Throwable failure) { throw io("Reading channel descriptor failed", failure); }
    }

    /** Create an unlinked, non-linkable regular file. The caller owns and closes it. */
    public static SeekableByteChannel openAnonymous(String directory) throws IOException {
        Path path = Path.of(directory);
        if (!path.isAbsolute()) throw new IllegalArgumentException("Library directory must be absolute");
        /* O_EXCL with O_TMPFILE prevents later linking this inode into the
           directory. Cleanup is closing our descriptor, never unlinking a
           pathname that might now identify someone else's file. */
        int raw = open(path, O_TMPFILE_EXCL_RDWR_CLOEXEC, 0600);
        FileChannel result = null;
        boolean transferred = false;
        try {
            long[] identity = stat(raw);
            if (!regular(identity) || identity[3] != 0)
                throw new IOException("O_TMPFILE did not create an anonymous regular file");
            transferred = true;
            result = channel(raw, true);
            synchronized (OWNED) { OWNED.put(result, new long[] {raw, identity[0], identity[1]}); }
            return result;
        } catch (Throwable failure) {
            try {
                if (result != null) result.close();
                else if (!transferred) closeRaw(raw);
            } catch (Throwable closing) { failure.addSuppressed(closing); }
            throw io("Creating anonymous library failed", failure);
        }
    }

    private static long[] ownedIdentity(SeekableByteChannel channel) throws IOException {
        /* Accept only this bridge's original channel, descriptor and inode.
           The WeakHashMap tracks ownership without keeping closed callers'
           channels alive; the live argument keeps this lookup's key alive. */
        final long[] identity;
        synchronized (OWNED) { identity = OWNED.get(channel); }
        if (identity == null) throw new IOException("Channel was not created by this bridge");
        int fd = descriptor(channel);
        long[] current = stat(fd);
        if (fd != identity[0] || !regular(current) || current[3] != 0
            || current[0] != identity[1] || current[1] != identity[2])
            throw new IOException("Anonymous channel identity changed");
        return new long[] {fd, current[0], current[1]};
    }

    private static byte[] hashLibrary(SeekableByteChannel channel) throws IOException {
        long[] identity = ownedIdentity(channel);
        FileChannel file = (FileChannel)channel;
        long[] before = stat((int)identity[0]);
        if (before[4] <= 0 || before[4] > MAX_LIBRARY)
            throw new IOException("Library must contain at most 16 MiB of nonempty data");
        final MessageDigest digest;
        try { digest = MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
        ByteBuffer buffer = ByteBuffer.allocate(8192);
        long total = 0;
        while (total < before[4]) {
            buffer.clear();
            buffer.limit((int)Math.min(buffer.capacity(), before[4] - total));
            int n = file.read(buffer, total);
            if (n <= 0) throw new IOException("Library became shorter while hashing");
            total += n;
            digest.update(buffer.array(), 0, n);
        }
        ownedIdentity(channel);
        if (!Arrays.equals(before, stat((int)identity[0])))
            throw new IOException("Library changed while hashing");
        return digest.digest();
    }

    /* The JNI registry keys libraries by the literal name. System.load canonicalizes
       /proc/self/fd/N, so an unrelated inode reusing N can hit an old cached library.
       Encode the held dev+ino as fixed-width equivalent dot/slash components. A loaded
       mapping retains its inode; its identity cannot be reused while that mapping lives. */
    private static String loadName(long[] identity) {
        StringBuilder name = new StringBuilder("/proc/self/fd/");
        for (int word = 1; word <= 2; word++)
            for (int bit = 63; bit >= 0; bit--)
                name.append(((identity[word] >>> bit) & 1) == 0 ? "./" : ".//");
        return name.append(identity[0]).toString();
    }

    private static void ensureLoaded(SeekableByteChannel channel) throws IOException {
        synchronized (LOAD_LOCK) {
            long[] identity = ownedIdentity(channel);
            byte[] requestedHash = hashLibrary(channel);
            if (loadedHash != null) {
                if (!MessageDigest.isEqual(loadedHash, requestedHash))
                    throw new SecurityException("Requested native library differs from the initially loaded library");
                return;
            }
            if (loadAttempted)
                throw new SecurityException("Previous native library load did not complete verification");
            try {
                Object libraries = LOADER_LIBRARIES.invoke(OwnedNativeCommand.class.getClassLoader());
                /* Native loading can have lasting effects before throwing.
                   Set this before entering the loader, and allow no retry
                   unless both the load and the post-load digest complete. */
                loadAttempted = true;
                if (LOAD_LIBRARY.invoke(libraries, OwnedNativeCommand.class, loadName(identity), false) == null)
                    throw new UnsatisfiedLinkError("Anonymous native library could not be loaded");
            } catch (Throwable failure) { throw io("Loading anonymous native library failed", failure); }
            byte[] afterLoad = hashLibrary(channel);
            if (!MessageDigest.isEqual(requestedHash, afterLoad))
                throw new SecurityException("Native library changed during loading");
            loadedHash = requestedHash;
        }
    }

    /**
     * Return metadata JSON, raw stdout and raw stderr as three byte arrays.
     * The caller must check native status and cleanup fields before using output.
     * Loading the library precedes the native command deadline.
     */
    public static byte[][] run(SeekableByteChannel library, String[] argv, int timeoutSeconds) throws IOException {
        if (argv == null || argv.length < 1 || argv.length > 64 || timeoutSeconds < 1 || timeoutSeconds > 300)
            throw new IllegalArgumentException("Expected 1-64 arguments and a timeout of 1-300 seconds");
        byte[][] encoded = new byte[argv.length][];
        int total = 0;
        for (int i = 0; i < argv.length; i++) {
            if (argv[i] == null || argv[i].indexOf('\0') >= 0)
                throw new IllegalArgumentException("Null argv element or embedded NUL");
            encoded[i] = argv[i].getBytes(StandardCharsets.UTF_8);
            total += encoded[i].length + 1;
            if (encoded[i].length > 32768 || total > 131072)
                throw new IllegalArgumentException("Argument limits exceeded");
        }
        if (!Path.of(argv[0]).isAbsolute()) throw new IllegalArgumentException("Executable path must be absolute");
        /* Library verification/loading is outside the native command deadline.
           invoke0 starts that deadline before inspecting the executable. */
        ensureLoaded(library);
        return invoke0(encoded, timeoutSeconds);
    }

    /* The standalone CLI accepts a local source pathname. Bind O_PATH first, reject
       non-regular objects, then reopen that exact inode nonblocking through procfs. */
    private static SeekableByteChannel copySource(Path source) throws IOException {
        if (!source.isAbsolute()) throw new IllegalArgumentException("Library path must be absolute");
        int pathFd = open(source, O_PATH_CLOEXEC, 0);
        int readFd = -1;
        FileChannel input = null;
        SeekableByteChannel output = null;
        try {
            long[] expected = stat(pathFd);
            if (!regular(expected) || expected[4] <= 0 || expected[4] > MAX_LIBRARY)
                throw new IOException("Source library must be a regular file of at most 16 MiB");
            readFd = open(Path.of("/proc/self/fd/" + pathFd), O_RDONLY_NONBLOCK_CLOEXEC, 0);
            if (!sameFile(expected, stat(readFd)))
                throw new IOException("Source library identity changed while reopening");
            int transferred = readFd;
            readFd = -1;
            input = channel(transferred, false);
            output = openAnonymous(source.getParent().toString());
            ByteBuffer buffer = ByteBuffer.allocate(8192);
            long total = 0;
            while (total < expected[4]) {
                buffer.clear();
                buffer.limit((int)Math.min(buffer.capacity(), expected[4] - total));
                int n = input.read(buffer);
                if (n <= 0) throw new IOException("Source library became shorter during copy");
                total += n;
                buffer.flip();
                while (buffer.hasRemaining())
                    if (output.write(buffer) <= 0)
                        throw new IOException("Anonymous library write made no progress");
            }
            if (!Arrays.equals(expected, stat(pathFd)))
                throw new IOException("Source library changed during copy");
            input.close();
            input = null;
            int closing = pathFd;
            pathFd = -1;
            closeRaw(closing);
            return output;
        } catch (Throwable failure) {
            try { if (output != null) output.close(); }
            catch (Throwable closing) { failure.addSuppressed(closing); }
            try { if (input != null) input.close(); }
            catch (Throwable closing) { failure.addSuppressed(closing); }
            try { if (readFd >= 0) closeRaw(readFd); }
            catch (Throwable closing) { failure.addSuppressed(closing); }
            try { if (pathFd >= 0) closeRaw(pathFd); }
            catch (Throwable closing) { failure.addSuppressed(closing); }
            throw io("Copying source library failed", failure);
        }
    }

    private static void print(byte[][] result) {
        System.out.println("{\"metadata\":" + new String(result[0], StandardCharsets.UTF_8)
            + ",\"stdout_base64\":\"" + Base64.getEncoder().encodeToString(result[1])
            + "\",\"stderr_base64\":\"" + Base64.getEncoder().encodeToString(result[2]) + "\"}");
    }

    /** Standalone loader test entry point; the Elasticsearch path calls run(). */
    public static void main(String[] args) throws Exception {
        if (args.length < 4) throw new IllegalArgumentException("library --filtered|--unfiltered timeout executable [arguments]");
        try (SeekableByteChannel library = copySource(Path.of(args[0]))) {
            ensureLoaded(library);
            if (args[1].equals("--filtered")) installFilterForTest0();
            else if (!args[1].equals("--unfiltered")) throw new IllegalArgumentException(args[1]);
            print(run(library, Arrays.copyOfRange(args, 3, args.length), Integer.parseInt(args[2])));
        }
    }
}
