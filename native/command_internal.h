/* Private types shared by the ELF loader, process supervisor and JNI adapter.
 * No application-facing API lives here. Program mappings belong to execute();
 * the result owns bounded output and the supervisor's completion record.
 */
#ifndef JAVA4SHELL_COMMAND_INTERNAL_H
#define JAVA4SHELL_COMMAND_INTERNAL_H
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>


#define MAX_ARGS 64
#define MAX_ARG_BYTES 131072
#define MAX_FILE (64u * 1024u * 1024u)
#define MAX_IMAGE (256u * 1024u * 1024u)
#define OUTPUT_LIMIT 65536
#define STACK_BYTES (8u * 1024u * 1024u)
#define CLONE_STACK_BYTES (1024u * 1024u)
#define RESULT_MAGIC 0x434d4431u
#ifndef JAVA4SHELL_CHILD_BATCH_SIZE
#define JAVA4SHELL_CHILD_BATCH_SIZE 1024
#endif
#if JAVA4SHELL_CHILD_BATCH_SIZE < 1 || JAVA4SHELL_CHILD_BATCH_SIZE > 1024
#error "JAVA4SHELL_CHILD_BATCH_SIZE must be between 1 and 1024"
#endif
#ifndef JAVA4SHELL_CHILDREN_PATH
#define JAVA4SHELL_CHILDREN_PATH "/proc/thread-self/children"
#endif
#ifndef PIDFD_IDTYPE
#define PIDFD_IDTYPE 3
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

enum stage {
    ST_NONE,
    ST_ARGV,
    ST_OPEN,
    ST_PERMISSION,
    ST_FILE_CHANGED,
    ST_ELF,
    ST_INTERPRETER,
    ST_ADDRESS_COLLISION,
    ST_MAP,
    ST_STACK,
    ST_PIPE,
    ST_CLONE,
    ST_SUBREAPER,
    ST_CHILD_FDS,
    ST_CHILD_SETUP,
    ST_WAIT,
    ST_TIMEOUT,
    ST_DESCENDANTS,
    ST_PROTOCOL,
    ST_KERNEL
};
struct error {
    int stage, number, unsupported;
};
struct file_image {
    unsigned char *bytes;
    size_t length;
    struct stat identity;
};
struct mapped {
    void *base;
    size_t length;
    uintptr_t bias, entry, phdr;
    uint16_t phnum;
    char interpreter[PATH_MAX];
};
struct program {
    struct mapped exe, interp;
    void *stack_map;
    size_t stack_length;
    uintptr_t stack;
};
struct output {
    unsigned char bytes[OUTPUT_LIMIT];
    size_t length;
    int truncated;
};
struct wire_result {
    /* Internal parent/supervisor protocol. This is never command stdout. */
    uint32_t magic;
    int stage, number, unsupported, child_pid, exit_code, term_signal, timed_out, cleanup_complete,
        descendants_reaped;
};
struct result {
    struct error error;
    struct output out, err;
    struct wire_result wire;
    pid_t supervisor;
    int supervisor_reaped, supervisor_status, no_new_privs, seccomp, protocol_complete;
    struct stat executable;
};
struct supervisor_args {
    const struct program *program;
    int protocol, out, err, devnull;
    uint64_t deadline;
    pid_t parent;
    void *command_stack;
};
struct command_args {
    const struct program *program;
    int setup_fd;
    pid_t parent;
};

static inline int fail(struct error *e, int stage, int number, int unsupported) {
    if (!e->stage) {
        e->stage = stage;
        e->number = number;
        e->unsupported = unsupported;
    }
    return -1;
}
static inline uint64_t monotonic_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static inline int deadline_check(struct error *e, uint64_t deadline) {
    return monotonic_ms() >= deadline ? fail(e, ST_TIMEOUT, ETIMEDOUT, 0) : 0;
}

/* Hidden symbols prevent another loaded library from interposing these internal
 * calls. program_release() accepts a partially prepared or zeroed program. */
__attribute__((visibility("hidden")))
int program_prepare(char **argv, int argc, struct program *p, struct stat *identity,
                    struct error *e, uint64_t deadline);
__attribute__((visibility("hidden")))
void program_release(struct program *p);
__attribute__((visibility("hidden")))
void execute(char **argv, int argc, int timeout, struct result *r);

#endif
