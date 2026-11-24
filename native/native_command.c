/* JNI adapter: validate arguments, invoke the supervised command, and return
 * metadata JSON plus raw stdout/stderr. The actual loader is elf_loader.c;
 * process ownership and timeouts are in process_supervisor.c.
 * Elasticsearch's syscall filter stays active. Only the standalone test entry
 * point below installs a filter; the application run() path never changes it.
 */
#include "command_internal.h"

static const char *stage_names[] = {
    "none",         "argv",        "open",        "permission",
    "file_changed", "elf",         "interpreter", "address_collision",
    "map",          "stack",       "pipe",        "clone",
    "subreaper",    "child_fds",   "child_setup", "wait",
    "timeout",      "descendants", "protocol",    "kernel"};
/* Standalone validation only: mirror the relevant Elasticsearch syscall
   denials. The application path neither installs nor relaxes a filter. */
static int install_filter(void) {
    struct sock_filter ins[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 7),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, 0x3fffffff, 5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 57, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 58, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 59, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 322, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES)};
    struct sock_fprog p = {(unsigned short)(sizeof ins / sizeof ins[0]), ins};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &p);
}
JNIEXPORT void JNICALL
Java_org_elasticsearch_painless_OwnedNativeCommand_installFilterForTest0(JNIEnv *env, jclass c) {
    (void)c;
    if (install_filter()) {
        jclass e = (*env)->FindClass(env, "java/io/IOException");
        if (e)
            (*env)->ThrowNew(env, e, "seccomp installation failed");
    }
}
/* JNI boundary: byte[][] {metadata JSON, raw stdout, raw stderr}. Validate argv
   again here because callers need not have used the Java run() wrapper. */
JNIEXPORT jobjectArray JNICALL Java_org_elasticsearch_painless_OwnedNativeCommand_invoke0(
    JNIEnv *env, jclass c, jobjectArray input, jint timeout) {
    (void)c;
    struct result *r = calloc(1, sizeof *r);
    char *argv[MAX_ARGS + 1] = {0};
    int argc = 0;
    size_t total = 0;
    if (!r)
        return NULL;
    r->wire.exit_code = -1;
    r->wire.child_pid = -1;
    r->supervisor = -1;
    if (!input || timeout < 1 || timeout > 300) {
        fail(&r->error, ST_ARGV, EINVAL, 1);
        goto result;
    }
    argc = (*env)->GetArrayLength(env, input);
    if (argc < 1 || argc > MAX_ARGS) {
        fail(&r->error, ST_ARGV, E2BIG, 1);
        goto result;
    }
    for (int i = 0; i < argc; i++) {
        jbyteArray a = (jbyteArray)(*env)->GetObjectArrayElement(env, input, i);
        if (!a) {
            fail(&r->error, ST_ARGV, EINVAL, 1);
            goto result;
        }
        jsize n = (*env)->GetArrayLength(env, a);
        if (n < 0 || n > 32768 || total + (size_t)n + 1 > MAX_ARG_BYTES) {
            (*env)->DeleteLocalRef(env, a);
            fail(&r->error, ST_ARGV, E2BIG, 1);
            goto result;
        }
        argv[i] = malloc((size_t)n + 1);
        if (!argv[i]) {
            (*env)->DeleteLocalRef(env, a);
            fail(&r->error, ST_ARGV, ENOMEM, 0);
            goto result;
        }
        (*env)->GetByteArrayRegion(env, a, 0, n, (jbyte *)argv[i]);
        (*env)->DeleteLocalRef(env, a);
        if ((*env)->ExceptionCheck(env))
            goto result;
        if (memchr(argv[i], 0, (size_t)n)) {
            fail(&r->error, ST_ARGV, EINVAL, 1);
            goto result;
        }
        argv[i][n] = 0;
        total += (size_t)n + 1;
    }
    if (!argv[0] || argv[0][0] != '/' || strlen(argv[0]) >= PATH_MAX) {
        fail(&r->error, ST_ARGV, EINVAL, 1);
        goto result;
    }
    execute(argv, argc, timeout, r);
result:
    for (int i = 0; i < MAX_ARGS; i++)
        free(argv[i]);
    if ((*env)->ExceptionCheck(env)) {
        free(r);
        return NULL;
    }
    struct error err = r->error;
    if (!err.stage && r->wire.stage) {
        err.stage = r->wire.stage;
        err.number = r->wire.number;
        err.unsupported = r->wire.unsupported;
    }
    int timed_out = r->wire.timed_out || r->error.stage == ST_TIMEOUT;
    /* The supervisor's complete protocol and ordinary exit are independent
       evidence. A vanished supervisor is not proof its descendants exited. */
    int cleanup_known =
        r->wire.cleanup_complete && r->supervisor_reaped && r->supervisor_status == 0;
    const char *status = err.unsupported                         ? "unsupported"
                         : timed_out                             ? "timeout"
                         : (r->supervisor > 0 && !cleanup_known) ? "cleanup_unknown"
                         : err.stage                             ? "error"
                         : cleanup_known                         ? "completed"
                                                                 : "cleanup_unknown";
    if (err.stage < 0 || err.stage > ST_KERNEL)
        err.stage = ST_PROTOCOL;
    char meta[1024];
    snprintf(meta, sizeof meta,
             "{\"status\":\"%s\",\"stage\":\"%s\",\"error_errno\":%d,\"supervisor_pid\":%ld,"
             "\"supervisor_reaped\":%s,\"supervisor_status\":%d,\"child_pid\":%d,\"exit_code\":%d,"
             "\"term_signal\":%d,\"timeout\":%s,\"cleanup_complete\":%s,\"descendants_reaped\":%d,"
             "\"stdout_truncated\":%s,\"stderr_truncated\":%s,\"no_new_privs\":%d,\"seccomp\":%d,"
             "\"executable_dev\":%llu,\"executable_ino\":%llu,\"executable_size\":%lld}",
             status, stage_names[err.stage], err.number, (long)r->supervisor,
             r->supervisor_reaped ? "true" : "false", r->supervisor_status, r->wire.child_pid,
             r->wire.exit_code, r->wire.term_signal, timed_out ? "true" : "false",
             r->wire.cleanup_complete ? "true" : "false", r->wire.descendants_reaped,
             r->out.truncated ? "true" : "false", r->err.truncated ? "true" : "false",
             r->no_new_privs, r->seccomp, (unsigned long long)r->executable.st_dev,
             (unsigned long long)r->executable.st_ino, (long long)r->executable.st_size);
    jclass bytes = (*env)->FindClass(env, "[B");
    jobjectArray array = bytes ? (*env)->NewObjectArray(env, 3, bytes, NULL) : NULL;
    const unsigned char *values[] = {(const unsigned char *)meta, r->out.bytes, r->err.bytes};
    size_t sizes[] = {strlen(meta), r->out.length, r->err.length};
    if (array)
        for (int i = 0; i < 3; i++) {
            jbyteArray b = (*env)->NewByteArray(env, (jsize)sizes[i]);
            if (!b) {
                array = NULL;
                break;
            }
            (*env)->SetByteArrayRegion(env, b, 0, (jsize)sizes[i], (const jbyte *)values[i]);
            (*env)->SetObjectArrayElement(env, array, i, b);
            (*env)->DeleteLocalRef(env, b);
            if ((*env)->ExceptionCheck(env)) {
                array = NULL;
                break;
            }
        }
    free(r);
    return array;
}
