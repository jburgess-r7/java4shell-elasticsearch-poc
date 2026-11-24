/* Own command execution outside the JVM.
 * execute() clones a supervisor, drains bounded output, and verifies its exit.
 * supervisor_start() becomes a subreaper and owns the command's descendants.
 * command_start() closes inherited descriptors and enters the prepared linker.
 * No CLONE_VM or CLONE_FILES sharing is used. The existing syscall filter,
 * credentials and no_new_privs state remain in force.
 */
#include "command_internal.h"

static __attribute__((noreturn, noinline)) void enter_program(uintptr_t entry, uintptr_t stack) {
    /* ld.so expects the initial stack in rsp and no supplied rtld_fini hook.
       It eventually transfers control to the executable's entry point. */
    __asm__ volatile(
        "movq %[stack], %%rsp\n\txor %%rdx, %%rdx\n\tjmp *%[entry]" ::[stack] "r"(stack),
        [entry] "r"(entry)
        : "rdx", "memory");
    __builtin_unreachable();
}
static int pipe_read_nonblock(int p[2]) {
    if (pipe2(p, O_CLOEXEC))
        return -1;
    int f = fcntl(p[0], F_GETFL);
    if (f < 0 || fcntl(p[0], F_SETFL, f | O_NONBLOCK)) {
        int save = errno;
        close(p[0]);
        close(p[1]);
        p[0] = p[1] = -1;
        errno = save;
        return -1;
    }
    return 0;
}
static void reset_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    for (int s = 1; s < NSIG; s++)
        if (s != SIGKILL && s != SIGSTOP)
            sigaction(s, &sa, NULL);
    sigset_t empty;
    sigemptyset(&empty);
    sigprocmask(SIG_SETMASK, &empty, NULL);
}
static void raw_exit(int code) {
    syscall(SYS_exit_group, code);
    for (;;) {
    }
}
static int pidfd_signal(int fd, int sig) {
    return (int)syscall(SYS_pidfd_send_signal, fd, sig, NULL, 0);
}
static int pidfd_wait(int fd, siginfo_t *si, int options) {
    memset(si, 0, sizeof *si);
    return (int)syscall(SYS_waitid, PIDFD_IDTYPE, fd, si, options, NULL);
}
static int process_api_check(struct error *e) {
    /* Fail before launch if this kernel/filter cannot identify, signal and
       wait on processes through pidfds. Numeric PIDs alone are reusable. */
    int fd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (fd < 0)
        return fail(e, ST_KERNEL, errno, 1);
    int number = 0;
    if (pidfd_signal(fd, 0))
        number = errno;
    if (!number) {
        siginfo_t si;
        errno = 0;
        int rc = pidfd_wait(fd, &si, WEXITED | WNOHANG);
        if (rc != -1 || errno != ECHILD)
            number = rc < 0 ? errno : EPROTO;
    }
    close(fd);
    return number ? fail(e, ST_KERNEL, number, 1) : 0;
}
static void wire_error(struct wire_result *w, int stage, int number, int unsupported) {
    if (!w->stage) {
        w->stage = stage;
        w->number = number;
        w->unsupported = unsupported;
    }
}
static int command_start(void *ptr) {
    const struct command_args *a = ptr;
    struct {
        int stage, number;
    } err = {ST_CHILD_SETUP, 0};
    if (syscall(SYS_prctl, PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0 ||
        syscall(SYS_getppid) != a->parent) {
        err.number = errno ? errno : ESRCH;
        goto error;
    }
    if (syscall(SYS_close_range, 3u, UINT_MAX, 0) < 0) {
        err.number = errno;
        goto error;
    }
    /* Only stdin/stdout/stderr survive. The JVM's sockets and the supervisor's
       result channel must never become descriptors owned by the command. */
    enter_program(a->program->interp.entry, a->program->stack);
error:
    syscall(SYS_write, a->setup_fd, &err, sizeof err);
    raw_exit(125);
    return 125;
}
struct child_reader {
    int fd, eof, digits;
    size_t next, length;
    unsigned long value;
    char buffer[4096];
};
static int children_open(struct child_reader *reader) {
    memset(reader, 0, sizeof *reader);
    reader->fd = open(JAVA4SHELL_CHILDREN_PATH, O_RDONLY | O_CLOEXEC);
    return reader->fd < 0 ? -1 : 0;
}
static void children_close(struct child_reader *reader) {
    if (reader->fd >= 0)
        close(reader->fd);
    reader->fd = -1;
}
static int read_children(struct child_reader *reader, pid_t *self, int *count) {
    *count = 0;
    while (!reader->eof) {
        if (reader->next == reader->length) {
            ssize_t got = read(reader->fd, reader->buffer, sizeof reader->buffer);
            if (got < 0 && errno == EINTR)
                continue;
            if (got < 0) {
                reader->eof = 1;
                return -1;
            }
            reader->next = 0;
            reader->length = (size_t)got;
            if (!got) {
                reader->eof = 1;
                if (reader->digits) {
                    if (!reader->value)
                        goto malformed;
                    self[(*count)++] = (pid_t)reader->value;
                }
                return 0;
            }
        }
        unsigned char c = (unsigned char)reader->buffer[reader->next++];
        if (c >= '0' && c <= '9') {
            if (reader->value > ((unsigned long)INT_MAX - (unsigned)(c - '0')) / 10)
                goto malformed;
            reader->value = reader->value * 10 + (unsigned)(c - '0');
            reader->digits = 1;
        } else if (c == ' ' || c == '\n') {
            if (!reader->digits)
                continue;
            if (!reader->value)
                goto malformed;
            self[(*count)++] = (pid_t)reader->value;
            reader->value = 0;
            reader->digits = 0;
            if (*count == JAVA4SHELL_CHILD_BATCH_SIZE)
                return 0;
        } else
            goto malformed;
    }
    return 0;
malformed:
    reader->eof = 1;
    errno = EOVERFLOW;
    return -1;
}
static void signal_descendant(pid_t child, struct wire_result *w) {
    int fd = (int)syscall(SYS_pidfd_open, child, 0);
    if (fd < 0) {
        if (errno != ESRCH)
            wire_error(w, ST_DESCENDANTS, errno, 0);
        return;
    }
    siginfo_t si;
    /* WNOWAIT verifies this pidfd still names one of our children without
       consuming its exit status. An unrelated live PID yields ECHILD. */
    if (pidfd_wait(fd, &si, WEXITED | WNOHANG | WNOWAIT))
        wire_error(w, ST_DESCENDANTS, errno, 0);
    else if (!si.si_pid && pidfd_signal(fd, SIGKILL) && errno != ESRCH)
        wire_error(w, ST_DESCENDANTS, errno, 0);
    close(fd);
}
static void cleanup_descendants(struct wire_result *w) {
    /* The dedicated subreaper owns orphaned grandchildren, including children
       that leave the command's process group. Repeat discovery after reaping
       because a descendant can become our direct child only when its parent
       exits. ECHILD is the evidence for complete cleanup. */
    uint64_t deadline = monotonic_ms() + 10000;
    pid_t children[JAVA4SHELL_CHILD_BATCH_SIZE];
    for (;;) {
        struct child_reader reader;
        if (children_open(&reader))
            wire_error(w, ST_DESCENDANTS, errno, 0);
        else {
            while (!reader.eof && monotonic_ms() < deadline) {
                int count = 0;
                int rc = read_children(&reader, children, &count);
                if (rc)
                    wire_error(w, ST_DESCENDANTS, errno, 0);
                // Signal complete entries even after a later parse/read error.
                // Reaping waits until this pass ends, so a slow first child
                // cannot hide later entries or consume the whole deadline.
                for (int i = 0; i < count; i++)
                    signal_descendant(children[i], w);
                if (rc)
                    break;
            }
            children_close(&reader);
        }
        for (;;) {
            if (monotonic_ms() >= deadline) {
                wire_error(w, ST_DESCENDANTS, ETIMEDOUT, 0);
                return;
            }
            siginfo_t si;
            memset(&si, 0, sizeof si);
            int rc = (int)syscall(SYS_waitid, P_ALL, 0, &si, WEXITED | WNOHANG, NULL);
            if (rc < 0 && errno == ECHILD) {
                w->cleanup_complete = 1;
                return;
            }
            if (rc == 0 && si.si_pid) {
                w->descendants_reaped++;
                continue;
            }
            if (rc < 0 && errno != EINTR) {
                wire_error(w, ST_DESCENDANTS, errno, 0);
                break;
            }
            if (rc < 0 && errno == EINTR)
                continue;
            break;
        }
        if (monotonic_ms() >= deadline) {
            wire_error(w, ST_DESCENDANTS, ETIMEDOUT, 0);
            return;
        }
        struct timespec t = {0, 1000000};
        nanosleep(&t, NULL);
    }
}
static int supervisor_fds(const struct supervisor_args *a, int *protocol) {
    int src[4] = {a->protocol, a->out, a->err, a->devnull}, tmp[4] = {-1, -1, -1, -1};
    for (int i = 0; i < 4; i++) {
        tmp[i] = fcntl(src[i], F_DUPFD_CLOEXEC, 64);
        if (tmp[i] < 0)
            return -1;
    }
    if (dup2(tmp[0], 3) < 0)
        return -1;
    *protocol = 3;
    if (dup2(tmp[1], 1) < 0 || dup2(tmp[2], 2) < 0 || dup2(tmp[3], 0) < 0)
        return -1;
    return (int)syscall(SYS_close_range, 4u, UINT_MAX, 0);
}
/* Own the command and any adopted descendants, then report status exactly once.
   The JNI caller owns this supervisor and independently verifies its exit. */
static int supervisor_start(void *ptr) {
    const struct supervisor_args *a = ptr;
    struct wire_result w = {
        .magic = RESULT_MAGIC, .exit_code = -1, .child_pid = -1, .cleanup_complete = 1};
    int protocol = a->protocol;
    int setup[2] = {-1, -1}, childfd = -1;
    pid_t child = -1;
    siginfo_t si;
    reset_signals();
    /* Parent-death signals cover the immediate ownership chain. The separate
       subreaper is still needed to collect commands that fork descendants. */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || getppid() != a->parent) {
        wire_error(&w, ST_CHILD_SETUP, errno ? errno : ESRCH, 0);
        goto done;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) {
        wire_error(&w, ST_SUBREAPER, errno, 1);
        goto done;
    }
    if (supervisor_fds(a, &protocol)) {
        wire_error(&w, ST_CHILD_FDS, errno, errno == ENOSYS);
        goto done;
    }
    protocol = 3;
    pid_t initial[JAVA4SHELL_CHILD_BATCH_SIZE];
    int initial_count = 0;
    struct child_reader initial_reader;
    if (children_open(&initial_reader)) {
        wire_error(&w, ST_DESCENDANTS, errno, 1);
        goto done;
    }
    int initial_rc = read_children(&initial_reader, initial, &initial_count);
    int initial_errno = errno;
    children_close(&initial_reader);
    if (initial_rc) {
        wire_error(&w, ST_DESCENDANTS, initial_errno, 1);
        if (initial_count) {
            w.cleanup_complete = 0;
            goto descendants;
        }
        goto done;
    }
    if (initial_count) {
        w.cleanup_complete = 0;
        wire_error(&w, ST_DESCENDANTS, EBUSY, 0);
        goto descendants;
    }
    if (pipe_read_nonblock(setup)) {
        wire_error(&w, ST_PIPE, errno, 0);
        goto descendants;
    }
    if (monotonic_ms() >= a->deadline) {
        w.timed_out = 1;
        wire_error(&w, ST_TIMEOUT, ETIMEDOUT, 0);
        goto descendants;
    }
    struct command_args ca = {a->program, setup[1], getpid()};
    child = clone(command_start, (char *)a->command_stack + CLONE_STACK_BYTES,
                  SIGCHLD | CLONE_PIDFD, &ca, &childfd, NULL, NULL);
    if (child < 0) {
        wire_error(&w, ST_CLONE, errno, errno == EINVAL || errno == ENOSYS);
        goto descendants;
    }
    w.child_pid = child;
    w.cleanup_complete = 0;
    close(setup[1]);
    setup[1] = -1;
    int reaped = 0;
    while (!reaped) {
        if (pidfd_wait(childfd, &si, WEXITED | WNOHANG) == 0) {
            if (si.si_pid) {
                reaped = 1;
                if (si.si_code == CLD_EXITED)
                    w.exit_code = si.si_status;
                else
                    w.term_signal = si.si_status;
                break;
            }
        } else if (errno != EINTR) {
            wire_error(&w, ST_WAIT, errno, 0);
            break;
        }
        if (monotonic_ms() >= a->deadline) {
            w.timed_out = 1;
            if (pidfd_signal(childfd, SIGKILL) && errno != ESRCH)
                wire_error(&w, ST_WAIT, errno, 0);
            for (;;) {
                if (pidfd_wait(childfd, &si, WEXITED) == 0) {
                    reaped = 1;
                    if (si.si_code == CLD_EXITED)
                        w.exit_code = si.si_status;
                    else
                        w.term_signal = si.si_status;
                    break;
                }
                if (errno != EINTR) {
                    wire_error(&w, ST_WAIT, errno, 0);
                    break;
                }
            }
            break;
        }
        struct timespec t = {0, 10000000};
        nanosleep(&t, NULL);
    }
    if (!reaped && childfd >= 0) {
        if (pidfd_signal(childfd, SIGKILL) && errno != ESRCH)
            wire_error(&w, ST_WAIT, errno, 0);
        while (pidfd_wait(childfd, &si, WEXITED) < 0 && errno == EINTR) {
        }
    }
    if (setup[0] >= 0) {
        struct {
            int stage, number;
        } ce;
        ssize_t n = read(setup[0], &ce, sizeof ce);
        if (n == (ssize_t)sizeof ce)
            wire_error(&w, ce.stage, ce.number, ce.number == ENOSYS);
        else if (n > 0)
            wire_error(&w, ST_PROTOCOL, EIO, 0);
    }
descendants:
    if (setup[0] >= 0)
        close(setup[0]);
    if (setup[1] >= 0)
        close(setup[1]);
    if (childfd >= 0)
        close(childfd);
    cleanup_descendants(&w);
done:
    syscall(SYS_write, protocol, &w, sizeof w);
    raw_exit(w.cleanup_complete ? 0 : 1);
    return 1;
}
static int output_read(int fd, struct output *o) {
    unsigned char b[4096];
    ssize_t n = read(fd, b, sizeof b);
    if (n == 0)
        return 0;
    if (n < 0)
        return (errno == EINTR || errno == EAGAIN) ? 1 : -1;
    size_t keep = (size_t)n;
    /* Keep draining after the public capture limit so a verbose command
       cannot deadlock against a full stdout/stderr pipe. */
    if (keep > OUTPUT_LIMIT - o->length) {
        keep = OUTPUT_LIMIT - o->length;
        o->truncated = 1;
    }
    memcpy(o->bytes + o->length, b, keep);
    o->length += keep;
    return 1;
}
void execute(char **argv, int argc, int timeout, struct result *r) {
    /* One deadline covers native file inspection, ELF/stack preparation and
       command execution. Java's library verification/loading precedes this
       function. The checks bound progress between preparation operations;
       they cannot interrupt a kernel call already blocked in filesystem I/O. */
    uint64_t deadline = monotonic_ms() + (uint64_t)timeout * 1000;
    struct program program = {0};
    int out[2] = {-1, -1}, err[2] = {-1, -1}, proto[2] = {-1, -1}, devnull = -1, superfd = -1;
    void *superstack = MAP_FAILED, *commandstack = MAP_FAILED;
    r->supervisor = -1;
    r->wire.exit_code = -1;
    r->wire.child_pid = -1;
    r->no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    r->seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (sysconf(_SC_PAGESIZE) != 4096) {
        fail(&r->error, ST_KERNEL, ENOTSUP, 1);
        goto done;
    }
    if (process_api_check(&r->error))
        goto done;
    if (program_prepare(argv, argc, &program, &r->executable, &r->error, deadline))
        goto done;
    if (pipe_read_nonblock(out) || pipe_read_nonblock(err) || pipe_read_nonblock(proto)) {
        fail(&r->error, ST_PIPE, errno, 0);
        goto done;
    }
    devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (devnull < 0) {
        fail(&r->error, ST_CHILD_FDS, errno, 0);
        goto done;
    }
    superstack = mmap(NULL, CLONE_STACK_BYTES, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    commandstack = mmap(NULL, CLONE_STACK_BYTES, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (superstack == MAP_FAILED || commandstack == MAP_FAILED) {
        fail(&r->error, ST_STACK, errno, 0);
        goto done;
    }
    if (deadline_check(&r->error, deadline))
        goto done;
    struct supervisor_args a = {&program, proto[1], out[1], err[1],
                                devnull, deadline, getpid(), commandstack};
    r->supervisor = clone(supervisor_start, (char *)superstack + CLONE_STACK_BYTES,
                          SIGCHLD | CLONE_PIDFD, &a, &superfd, NULL, NULL);
    if (r->supervisor < 0) {
        fail(&r->error, ST_CLONE, errno, errno == EINVAL || errno == ENOSYS);
        goto done;
    }
    close(out[1]);
    out[1] = -1;
    close(err[1]);
    err[1] = -1;
    close(proto[1]);
    proto[1] = -1;
    close(devnull);
    devnull = -1;
    struct pollfd f[3] = {{out[0], POLLIN, 0}, {err[0], POLLIN, 0}, {proto[0], POLLIN, 0}};
    size_t protocol_bytes = 0;
    int active = 3;
    /* Allow the supervisor time to kill/reap descendants after the command's
       deadline. If it is lost or killed, its missing successful result is
       reported as unknown cleanup; reaping it alone proves less than that. */
    uint64_t cleanup_deadline = deadline + 20000;
    siginfo_t si;
    while (active || !r->supervisor_reaped) {
        if (!r->supervisor_reaped) {
            int wr = pidfd_wait(superfd, &si, WEXITED | WNOHANG);
            if (wr == 0 && si.si_pid) {
                r->supervisor_reaped = 1;
                r->supervisor_status = si.si_code == CLD_EXITED ? si.si_status : 128 + si.si_status;
            } else if (wr < 0 && errno != EINTR) {
                fail(&r->error, ST_WAIT, errno, 0);
                break;
            }
        }
        if (monotonic_ms() >= cleanup_deadline) {
            fail(&r->error, ST_TIMEOUT, ETIMEDOUT, 0);
            if (!r->supervisor_reaped && pidfd_signal(superfd, SIGKILL) && errno != ESRCH)
                fail(&r->error, ST_WAIT, errno, 0);
            break;
        }
        int n = poll(f, 3, 50);
        if (n < 0 && errno != EINTR) {
            fail(&r->error, ST_PIPE, errno, 0);
            break;
        }
        for (int i = 0; i < 3; i++)
            if (f[i].fd >= 0 && (f[i].revents & (POLLIN | POLLHUP | POLLERR))) {
                int dr = 1;
                if (i < 2)
                    dr = output_read(f[i].fd, i ? &r->err : &r->out);
                else {
                    if (protocol_bytes >= sizeof r->wire) {
                        fail(&r->error, ST_PROTOCOL, EOVERFLOW, 0);
                        break;
                    }
                    ssize_t got = read(f[i].fd, (char *)&r->wire + protocol_bytes,
                                       sizeof r->wire - protocol_bytes);
                    if (got > 0) {
                        protocol_bytes += (size_t)got;
                        if (protocol_bytes == sizeof r->wire) {
                            r->protocol_complete = 1;
                            dr = 0;
                        }
                    } else if (got == 0)
                        dr = 0;
                    else if (errno != EINTR && errno != EAGAIN)
                        dr = -1;
                }
                if (dr <= 0) {
                    if (dr < 0)
                        fail(&r->error, ST_PIPE, errno, 0);
                    close(f[i].fd);
                    if (i == 0)
                        out[0] = -1;
                    else if (i == 1)
                        err[0] = -1;
                    else
                        proto[0] = -1;
                    f[i].fd = -1;
                    active--;
                }
            }
    }
    if (!r->supervisor_reaped) {
        if (pidfd_signal(superfd, SIGKILL) && errno != ESRCH && !r->error.stage)
            fail(&r->error, ST_WAIT, errno, 0);
        for (;;) {
            if (pidfd_wait(superfd, &si, WEXITED) == 0) {
                r->supervisor_reaped = 1;
                r->supervisor_status = si.si_code == CLD_EXITED ? si.si_status : 128 + si.si_status;
                break;
            }
            if (errno != EINTR) {
                if (!r->error.stage)
                    fail(&r->error, ST_WAIT, errno, 0);
                break;
            }
        }
    }
    if (!r->error.stage && (!r->protocol_complete || r->wire.magic != RESULT_MAGIC))
        fail(&r->error, ST_PROTOCOL, EIO, 0);
done:
    for (int i = 0; i < 2; i++) {
        if (out[i] >= 0)
            close(out[i]);
        if (err[i] >= 0)
            close(err[i]);
        if (proto[i] >= 0)
            close(proto[i]);
    }
    if (devnull >= 0)
        close(devnull);
    if (superfd >= 0)
        close(superfd);
    if (superstack != MAP_FAILED)
        munmap(superstack, CLONE_STACK_BYTES);
    if (commandstack != MAP_FAILED)
        munmap(commandstack, CLONE_STACK_BYTES);
    program_release(&program);
}
