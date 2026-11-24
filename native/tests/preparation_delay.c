#define _GNU_SOURCE
#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

// The manual regression preloads this only into its owned standalone JVM.
// Delay one read of the selected regular file to exercise the real deadline.
ssize_t pread(int fd, void *buffer, size_t count, off_t offset) {
    static atomic_flag delayed = ATOMIC_FLAG_INIT;
    const char *path = getenv("JAVA4SHELL_PREPARE_DELAY_FILE");
    struct stat expected, actual;
    if (path && !stat(path, &expected) && !fstat(fd, &actual) &&
        S_ISREG(actual.st_mode) && expected.st_dev == actual.st_dev &&
        expected.st_ino == actual.st_ino &&
        !atomic_flag_test_and_set_explicit(&delayed, memory_order_relaxed)) {
        struct timespec pause = {1, 500000000};
        while (nanosleep(&pause, &pause) && errno == EINTR) {
        }
    }
    return syscall(SYS_pread64, fd, buffer, count, offset);
}
