/* Standalone regression only: observe owned anonymous files and intercept
 * explicitly selected owned pathname/load boundaries. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int anonymous_fd = -1;

static void trace(const char *event, int fd, int flags, int result) {
    const char *path = getenv("JAVA4SHELL_TRACE_PATH");
    if (!path) return;
    int saved_errno = errno;
    struct stat st = {0};
    int have_stat = fd >= 0 && syscall(SYS_fstat, fd, &st) == 0;
    char line[512];
    int length = snprintf(line, sizeof(line),
        "{\"event\":\"%s\",\"fd\":%d,\"flags\":%d,\"result\":%d,"
        "\"stat\":%s,\"dev\":%llu,\"ino\":%llu,\"nlink\":%llu}\n",
        event, fd, flags, result, have_stat ? "true" : "false",
        (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
        (unsigned long long)st.st_nlink);
    int output = (int)syscall(SYS_openat, AT_FDCWD, path,
                             O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0);
    if (output < 0 || length < 0 || (size_t)length >= sizeof(line)
            || syscall(SYS_write, output, line, (size_t)length) != length)
        _exit(122);
    (void)syscall(SYS_close, output);
    errno = saved_errno;
}

static int named_path(const char *path) {
    const char *wanted = getenv("JAVA4SHELL_SWAP_PATH");
    return wanted && !strcmp(path, wanted);
}
static int selected(const char *stage, const char *path) {
    const char *wanted = getenv("JAVA4SHELL_SWAP_STAGE");
    return wanted && !strcmp(stage, wanted) && named_path(path);
}
static void swap_path(const char *path) {
    const char *replacement = getenv("JAVA4SHELL_SWAP_REPLACEMENT");
    /* One atomic overwrite is essential: it unlinks the original inode.
     * Moving the original to a saved name misses the reviewed false pass. */
    if (!replacement || syscall(SYS_renameat, AT_FDCWD, replacement, AT_FDCWD, path))
        _exit(121);
    trace("named_swap", -1, 0, 0);
}
static mode_t get_mode(int flags, va_list ap) {
    return (flags & O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE)
        ? (mode_t)va_arg(ap, int) : 0;
}
static int hooked_open(int dirfd, const char *path, int flags, mode_t mode) {
    if (named_path(path)) trace("named_open", -1, flags, 0);
    if ((flags & O_ACCMODE) == O_RDONLY && !(flags & O_CREAT)
            && selected("read-open", path))
        swap_path(path);
    int fd = (int)syscall(SYS_openat, dirfd, path, flags, mode);
    int saved_errno = errno;
    if (fd >= 0 && (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)
            && selected("open", path))
        swap_path(path);
    const char *directory = getenv("JAVA4SHELL_ANON_DIRECTORY");
    if ((flags & O_TMPFILE) == O_TMPFILE && directory && !strcmp(directory, path)) {
        if (fd >= 0) anonymous_fd = fd;
        trace("anonymous_open", fd, flags, fd >= 0 ? 0 : saved_errno);
    }
    errno = saved_errno;
    return fd;
}
static int hooked_unlink(int dirfd, const char *path, int flags) {
    if (named_path(path)) trace("named_unlink", -1, flags, 0);
    if (selected("unlink", path)) swap_path(path);
    return (int)syscall(SYS_unlinkat, dirfd, path, flags);
}
int open(const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = get_mode(flags, ap); va_end(ap);
    return hooked_open(AT_FDCWD, path, flags, mode);
}
int open64(const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = get_mode(flags, ap); va_end(ap);
    return hooked_open(AT_FDCWD, path, flags, mode);
}
int openat(int dirfd, const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = get_mode(flags, ap); va_end(ap);
    return hooked_open(dirfd, path, flags, mode);
}
int openat64(int dirfd, const char *path, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = get_mode(flags, ap); va_end(ap);
    return hooked_open(dirfd, path, flags, mode);
}
int unlink(const char *path) { return hooked_unlink(AT_FDCWD, path, 0); }
int unlinkat(int dirfd, const char *path, int flags) { return hooked_unlink(dirfd, path, flags); }

void *dlopen(const char *path, int flags) {
    static void *(*real_dlopen)(const char *, int);
    if (!real_dlopen) *(void **)(&real_dlopen) = dlsym(RTLD_NEXT, "dlopen");
    if (!real_dlopen) _exit(123);
    const char *last = path ? strrchr(path, '/') : NULL;
    char *end = NULL;
    long fd = last ? strtol(last + 1, &end, 10) : -1;
    if (path && !strncmp(path, "/proc/self/fd/", 14) && last && end && !*end
            && fd >= 0 && fd == anonymous_fd) {
        trace("anonymous_load", (int)fd, flags, 0);
        const char *mode = getenv("JAVA4SHELL_LOAD_FAILURE");
        if (mode && !strcmp(mode, "1")) {
            /* Populate the real loader's error state without loading any
             * replacement object, so the genuine Java load path fails. */
            return real_dlopen("/proc/self/fd/-1/java4shell-owned-load-failure", flags);
        }
    }
    return real_dlopen(path, flags);
}
