#define _GNU_SOURCE
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int reviewed_open(const char *path, int flags, ...);
#define open reviewed_open
#include "../elf_loader.c"
#include "../process_supervisor.c"
#include "../native_command.c"
#undef open

static const char *replace_path, *saved_path;
static int replaced, replacement_error;

static int reviewed_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    if (replace_path && !replaced && !strncmp(path, "/proc/self/fd/", 14)) {
        replaced = 1;
        if (rename(replace_path, saved_path) || mkfifo(replace_path, 0600))
            replacement_error = errno;
    }
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}

int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    struct stat original, current, saved;
    if (stat(argv[1], &original) || !S_ISREG(original.st_mode))
        return 3;
    replace_path = argv[1];
    saved_path = argv[2];
    struct file_image image = {0};
    struct error error = {0};
    int rc = file_read(argv[1], &image, &error, monotonic_ms() + 1000);
    int exact = rc == 0 && image.identity.st_dev == original.st_dev &&
                image.identity.st_ino == original.st_ino;
    int refused = rc == -1 && error.stage == ST_FILE_CHANGED && error.number == ESTALE;
    int okay = replaced && !replacement_error && !stat(argv[1], &current) &&
               S_ISFIFO(current.st_mode) && !stat(argv[2], &saved) &&
               saved.st_dev == original.st_dev && saved.st_ino == original.st_ino &&
               (exact || refused);
    file_release(&image);
    printf("{\"path_replaced_with_fifo\":%s,\"original_inode_or_refusal\":%s,"
           "\"stage\":\"%s\"}\n", okay ? "true" : "false",
           (exact || refused) ? "true" : "false", stage_names[error.stage]);
    return okay ? 0 : 1;
}
