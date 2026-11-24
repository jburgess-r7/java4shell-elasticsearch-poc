# Native command bridge

Elasticsearch 7.17.29's Linux syscall filter blocks normal process execution.
This bridge maps a selected executable and its dynamic linker into a separate
child, then enters the linker without calling `execve` or `execveat`. The
existing syscall filter remains in force. See Elasticsearch's
[filter source](https://github.com/elastic/elasticsearch/blob/580aff1a0064ce4c93293aaab6fcc55e22c10d1c/server/src/main/java/org/elasticsearch/bootstrap/SystemCallFilter.java)
and Rapid7's earlier [work on running ELF programs without execve](https://www.rapid7.com/blog/post/2019/01/03/santas-elfs-running-linux-executables-without-execve/).

From the repository root, build with a Linux x86-64 C compiler and JDK 17 or
later:

```bash
python3 -B native/build.py \
  --jdk .validation-local/runtimes/temurin21 \
  --output .validation-local/native-command
```

The output directory must be new. `build.json` records the source hashes,
compiler commands, Java class, shared library and bridge identity. The build
does not download a dependency or include a Java runtime. Build on a system
whose libc is compatible with the target. The recorded build used GCC 13.3
and glibc 2.39; its highest required glibc symbol version is 2.33.

To check the bridge separately from the CVE, run a disposable JVM with the
matching test filter:

```bash
.validation-local/runtimes/temurin21/bin/java \
  -cp .validation-local/native-command/classes \
  org.elasticsearch.painless.OwnedNativeCommand \
  "$PWD/.validation-local/native-command/libowned-native-command.so" \
  --filtered 60 /usr/bin/id -u
```

The JSON includes the real command status and Base64-encoded streams. This
standalone check does not establish exploitation of Elasticsearch.
For a source walkthrough, see [native execution and ownership](../docs/code-guide.md#native-execution-and-ownership).

The bridge accepts an absolute executable path and explicit arguments. It
currently supports dynamically linked x86-64 PIE ELF files, 4 KiB pages, and
Linux kernels with pidfd, `close_range` and `faccessat2` support. The process
must also be able to read its procfs descriptor and child entries. It rejects
scripts, static/non-PIE files, set-ID executables and file capabilities. There
are at most 64 arguments, 32 KiB per argument, and 128 KiB in total.
The selected file must have execute permission. Executable-stack and
unsupported ELF layouts are rejected; the file is limited to 64 MiB and
the mapped image to 256 MiB. The target directory used by the HTTP client
must be on a filesystem that supports `O_TMPFILE` and permits loading the
anonymous native library. There is no named-file fallback. A `noexec` mount
can prevent loading. The proof also requires the original SecurityManager
to deny the write permission for its proof path, so `--remote-dir` must be outside
the directories Elasticsearch normally permits the supplied class to write.
The client defaults to `/tmp`; Elasticsearch's own `ES_TMPDIR` is unsuitable
when it already grants that access.

The bridge creates the library with mode `0600` and
[`O_TMPFILE|O_EXCL`](https://man7.org/linux/man-pages/man2/open.2.html).
It has no directory entry and cannot subsequently be linked. The request
retains the read/write channel, verifies the written bytes, and closes that
channel after the command or a failed write/load. It reports the anonymous
file and descriptor-closure checks separately; it does not claim that closing
the channel unloads native code. The public client creates no marker file.
The controlled local comparison still creates and independently verifies
its exact marker bytes.

In the tested Intel SDE 10.13.1 route, image instrumentation also retains
a separate read-only handle to the loaded anonymous library. The native
and genuine-JVM checks distinguish that handle from the request's closed
read/write channel. Loaded code and the instrumentation handle can remain
until the image is unloaded or the disposable JVM exits. Freshly compiled
Painless scripts can use separate classloaders and load separate images.

The loader uses the pinned Linux JDK's internal file-descriptor and JNI
library-registration APIs through `jdk.unsupported`; no launcher
module-opening flag is added. Its raw procfs load name encodes the held
inode identity, preventing a reused descriptor number from selecting a
previously cached library. A failed first load makes that bridge instance
reject later loads. These operations require the supported Java 17/21
internals. Access that lets another process alter the JVM itself or mutate
its open descriptors is outside the tested protection against pathname
replacement.

Standard input is `/dev/null`. The environment contains a fixed `PATH` and C
locale. Each output stream is capped at 64 KiB, with truncation reported.
Timeouts are 1–300 seconds. The native deadline starts when `execute()`
begins, after native-library loading and Java/JNI argument validation and
copying. It includes reading and validating the executable
and its interpreter, ELF mapping, stack setup, supervisor startup and command
execution. The bridge rejects non-regular paths before opening them for
I/O, binds readable descriptors to the selected regular files, and checks
the deadline between bounded preparation steps. A kernel or filesystem call
that does not return cannot be forcibly interrupted by these checkpoints.
Cleanup has a separate allowance. A supervisor owns the command through a
pidfd and reaps adopted descendants; incomplete cleanup is an error. Programs
that launch other executables still encounter the original syscall filter,
and `/proc/self/exe` retains the original JVM executable identity. This is
not an interactive-shell implementation.

The bridge checks its pidfd operations before starting a supervisor, then
checks `/proc/thread-self/children` before starting the selected command.
Cleanup streams the child list and signals verified children before reaping
them. Persistent kernel/proc errors, unkillable children, or termination of
the supervisor by the command or an operator can still leave cleanup unknown.
The [manual native regression](tests/README.md) exercises these prerequisites,
multiple enumeration batches and real process cleanup.

The Java API is `OwnedNativeCommand.openAnonymous(String directory)`, followed
by `run(SeekableByteChannel library, String[] argv, int timeoutSeconds)`.
The caller owns and closes the returned channel. `run` returns three byte
arrays: metadata JSON, stdout and stderr. The request class checks the bridge
build identity, and the bridge rejects a different library after the first
load in a classloader. Loaded classes and native code remain until the JVM
exits.

The ELF parser, mapper, initial stack and process supervision code are local
to this project. The three-instruction x86-64 entry handoff was adapted from
[Rapid7 libreflect](https://github.com/rapid7/mettle/blob/98c61149d1e2ca769f7d27f96960c42633548903/libreflect/arch/linux/x86_64/arch_jump.h).
Its [BSD notice](third-party/libreflect-COPYING) is retained. That notice does
not select a license for the rest of this repository.

## Source layout

| File | Responsibility |
|---|---|
| [native_command.c](native_command.c) | JNI argument checks, response serialization and the standalone test-filter entry point. |
| [elf_loader.c](elf_loader.c) | Descriptor-bound reads, ELF validation, memory mappings and the initial stack. |
| [process_supervisor.c](process_supervisor.c) | Child launch, output collection, deadlines and descendant cleanup. |
| [command_internal.h](command_internal.h) | Private structures and ownership contracts between those components. Internal cross-file calls have hidden visibility. |
| [OwnedNativeCommand.java](java/org/elasticsearch/painless/OwnedNativeCommand.java) | Anonymous-library ownership and the Java/JNI boundary. |

The build compiles all three C files into one library and hashes every C/header
input into its build identity. The native tests verify the same input inventory.
