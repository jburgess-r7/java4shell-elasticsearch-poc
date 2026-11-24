#define JAVA4SHELL_CHILD_BATCH_SIZE 2
#define JAVA4SHELL_CHILDREN_PATH "children-input"
#include "../elf_loader.c"
#include "../process_supervisor.c"
#include "../native_command.c"

int main(void) {
    int result = 1, victimfd = -1, watcherfd = -1, status;
    pid_t victim = fork(), watcher = -1;
    if (victim < 0) return 2;
    if (victim == 0) { for (;;) pause(); }
    victimfd = (int)syscall(SYS_pidfd_open, victim, 0);
    if (victimfd < 0) goto done;
    int input = open(JAVA4SHELL_CHILDREN_PATH, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
    if (input < 0) goto done;
    if (dprintf(input, "%ld invalid-token\n", (long)victim) < 0) { close(input); goto done; }
    close(input);
    pid_t parsed[JAVA4SHELL_CHILD_BATCH_SIZE];
    int count = 0;
    struct child_reader reader;
    if (children_open(&reader)) goto done;
    errno = 0;
    int scan_result = read_children(&reader, parsed, &count);
    int scan_errno = errno;
    children_close(&reader);
    if (scan_result != -1 || scan_errno != EOVERFLOW || count != 1 || parsed[0] != victim)
        goto done;
    watcher = fork();
    if (watcher < 0) goto done;
    if (watcher == 0) {
        struct pollfd p = {victimfd, POLLIN, 0};
        if (poll(&p, 1, 5000) <= 0) raw_exit(10);
        int out = open(JAVA4SHELL_CHILDREN_PATH, O_TRUNC | O_WRONLY | O_CLOEXEC);
        if (out < 0) raw_exit(11);
        close(out);
        raw_exit(0);
    }
    watcherfd = (int)syscall(SYS_pidfd_open, watcher, 0);
    if (watcherfd < 0) goto done;
    struct wire_result wire = {0};
    cleanup_descendants(&wire);
    if (wire.stage == ST_DESCENDANTS && wire.number == EOVERFLOW && wire.cleanup_complete == 1 &&
        wire.descendants_reaped == 2) {
        errno = 0;
        if (waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD)
            result = 0;
    }
    printf("{\"partial_entries_retained\":true,\"error_preserved\":%s,\"cleanup_complete\":%s,"
           "\"descendants_reaped\":%d}\n", wire.stage == ST_DESCENDANTS ? "true" : "false",
           wire.cleanup_complete ? "true" : "false", wire.descendants_reaped);
done:
    if (victimfd >= 0) { pidfd_signal(victimfd, SIGKILL); close(victimfd); }
    if (watcherfd >= 0) { pidfd_signal(watcherfd, SIGKILL); close(watcherfd); }
    while (waitpid(-1, &status, 0) > 0 || errno == EINTR) {}
    return result;
}
