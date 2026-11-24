#define _GNU_SOURCE
#include <jni.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* The production bridge never installs this filter. This independent test entry
 * allows its very first anonymous-library load to run under the ES blacklist. */
JNIEXPORT void JNICALL Java_NativeLibraryFixture_installFilter0(JNIEnv *env, jclass cls) {
    (void)cls;
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
    struct sock_fprog program = {(unsigned short)(sizeof ins / sizeof ins[0]), ins};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        || syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &program)) {
        jclass error = (*env)->FindClass(env, "java/io/IOException");
        if (error) (*env)->ThrowNew(env, error, "owned test filter installation failed");
    }
}

JNIEXPORT jboolean JNICALL Java_NativeLibraryFixture_checkFilter0(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    char *argv[] = {(char *)"/owned-nonexistent-filter-check", NULL};
    errno = 0;
    long result = syscall(SYS_execve, argv[0], argv, NULL);
    int saved = errno;
    return result == -1 && saved == EACCES
        && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1
        && prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2;
}

/* A distinct, harmless JNI image proves that a recycled descriptor number
 * really loads new bytes. It never starts a process. */
JNIEXPORT jobjectArray JNICALL Java_org_elasticsearch_painless_OwnedNativeCommand_invoke0(
    JNIEnv *env, jclass cls, jobjectArray argv, jint timeout) {
    (void)cls; (void)argv; (void)timeout;
    const char *parts[] = {"{\"status\":\"harmless-alternate-image\"}", "different-image\n", ""};
    jclass bytes = (*env)->FindClass(env, "[B");
    if (!bytes) return NULL;
    jobjectArray result = (*env)->NewObjectArray(env, 3, bytes, NULL);
    if (!result) return NULL;
    for (int i = 0; i < 3; ++i) {
        jsize size = (jsize)strlen(parts[i]);
        jbyteArray part = (*env)->NewByteArray(env, size);
        if (!part) return NULL;
        (*env)->SetByteArrayRegion(env, part, 0, size, (const jbyte *)parts[i]);
        (*env)->SetObjectArrayElement(env, result, i, part);
        (*env)->DeleteLocalRef(env, part);
    }
    return result;
}

ssize_t write(int fd, const void *buffer, size_t size) {
    static ssize_t (*real_write)(int, const void *, size_t);
    if (!real_write) *(void **)(&real_write) = dlsym(RTLD_NEXT, "write");
    if (!real_write) _exit(121);
    if (getenv("JAVA4SHELL_NATIVE_ZERO_WRITE") && size) {
        struct stat identity;
        if (!fstat(fd, &identity) && S_ISREG(identity.st_mode) && identity.st_nlink == 0)
            return 0;
    }
    return real_write(fd, buffer, size);
}

void *dlopen(const char *path, int flags) {
    static void *(*real_dlopen)(const char *, int);
    static int changed;
    if (!real_dlopen) *(void **)(&real_dlopen) = dlsym(RTLD_NEXT, "dlopen");
    if (!real_dlopen) _exit(122);
    void *result = real_dlopen(path, flags);
    if (result && !changed && path && !strncmp(path, "/proc/self/fd/", 14)
        && getenv("JAVA4SHELL_NATIVE_MUTATE_LOAD")) {
        /* Change an unused ELF-ident padding byte after the genuine loader has
         * mapped the owned anonymous image. The bridge's post-load digest must
         * reject it and poison later load attempts in this bridge class. */
        int fd = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
        struct stat identity;
        unsigned char padding = 1;
        if (fd < 0 || fstat(fd, &identity) || !S_ISREG(identity.st_mode)
            || identity.st_nlink != 0 || pwrite(fd, &padding, 1, 9) != 1)
            _exit(123);
        close(fd);
        changed = 1;
    }
    return result;
}
