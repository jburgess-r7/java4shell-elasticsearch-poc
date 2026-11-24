/* Read and map a supported PIE executable and its ELF interpreter.
 * Descriptor identity checks bind each read to the selected regular file.
 * Preparation checks the caller's deadline and leaves every acquired mapping
 * in struct program, including on failure, for program_release() to undo.
 * No process is launched here.
 */
#include "command_internal.h"

static size_t page_up(size_t v) { return (v + 4095u) & ~(size_t)4095u; }
static int is_power2(uint64_t n) { return n && !(n & (n - 1)); }
static int same_stat(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static void file_release(struct file_image *f) {
    free(f->bytes);
    memset(f, 0, sizeof *f);
}
static int file_read(const char *path, struct file_image *f, struct error *e,
                     uint64_t deadline) {
    int pathfd = -1, fd = -1, rc = -1;
    struct stat selected, after;
    char descriptor_path[64];
    ssize_t n;
    if (path[0] != '/' || strlen(path) >= PATH_MAX)
        return fail(e, ST_ARGV, EINVAL, 1);
    if (deadline_check(e, deadline))
        return -1;
    // O_PATH acquires the object without opening a FIFO or device for I/O.
    // Reopen this exact descriptor only after its regular-file check, so
    // replacing the original pathname cannot substitute a blocking object.
    pathfd = open(path, O_PATH | O_CLOEXEC);
    if (pathfd < 0)
        return fail(e, ST_OPEN, errno, 0);
    if (fstat(pathfd, &selected)) {
        fail(e, ST_OPEN, errno, 0);
        goto done;
    }
    if (!S_ISREG(selected.st_mode) || selected.st_size < (off_t)sizeof(Elf64_Ehdr) ||
        selected.st_size > MAX_FILE) {
        fail(e, ST_ELF, ENOEXEC, 1);
        goto done;
    }
    if (deadline_check(e, deadline))
        goto done;
    int length = snprintf(descriptor_path, sizeof descriptor_path, "/proc/self/fd/%d", pathfd);
    if (length < 0 || (size_t)length >= sizeof descriptor_path) {
        fail(e, ST_OPEN, ENAMETOOLONG, 0);
        goto done;
    }
    fd = open(descriptor_path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &f->identity)) {
        fail(e, ST_OPEN, errno, 0);
        goto done;
    }
    if (!S_ISREG(f->identity.st_mode) || !same_stat(&selected, &f->identity)) {
        fail(e, ST_FILE_CHANGED, ESTALE, 0);
        goto done;
    }
    if (deadline_check(e, deadline))
        goto done;
    /* Userspace loading cannot reproduce privileged exec transitions. Require
       the caller's effective execute permission and reject set-ID/capability
       images instead of giving those files different semantics from exec. */
    if (f->identity.st_mode & (S_ISUID | S_ISGID)) {
        fail(e, ST_PERMISSION, EPERM, 1);
        goto done;
    }
    if (syscall(SYS_faccessat2, fd, "", X_OK, AT_EMPTY_PATH | AT_EACCESS)) {
        fail(e, ST_PERMISSION, errno, errno == EACCES || errno == EPERM || errno == ENOSYS);
        goto done;
    }
    n = fgetxattr(fd, "security.capability", NULL, 0);
    if (n > 0) {
        fail(e, ST_PERMISSION, EPERM, 1);
        goto done;
    }
    if (n < 0 && errno != ENODATA && errno != ENOTSUP && errno != EOPNOTSUPP) {
        fail(e, ST_PERMISSION, errno, 1);
        goto done;
    }
    if (deadline_check(e, deadline))
        goto done;
    f->length = (size_t)f->identity.st_size;
    f->bytes = malloc(f->length);
    if (!f->bytes) {
        fail(e, ST_OPEN, ENOMEM, 0);
        goto done;
    }
    size_t off = 0;
    while (off < f->length) {
        if (deadline_check(e, deadline))
            goto done;
        n = pread(fd, f->bytes + off, f->length - off, (off_t)off);
        int read_errno = errno;
        if (deadline_check(e, deadline))
            goto done;
        if (n < 0 && read_errno == EINTR)
            continue;
        if (n <= 0) {
            fail(e, ST_OPEN, n < 0 ? read_errno : EIO, 0);
            goto done;
        }
        off += (size_t)n;
    }
    if (fstat(fd, &after)) {
        fail(e, ST_FILE_CHANGED, errno, 0);
        goto done;
    }
    if (!same_stat(&f->identity, &after)) {
        fail(e, ST_FILE_CHANGED, ESTALE, 0);
        goto done;
    }
    if (deadline_check(e, deadline))
        goto done;
    rc = 0;
done:
    if (fd >= 0)
        close(fd);
    if (pathfd >= 0)
        close(pathfd);
    if (rc)
        file_release(f);
    return rc;
}
static int range_inside(uint64_t start, uint64_t len, uint64_t lower, uint64_t upper) {
    return start >= lower && start <= upper && len <= upper - start;
}
/* Accept the narrow layout this loader can reproduce: x86-64 ET_DYN images,
   one dynamic segment, and one interpreter for the main executable. The
   interpreter will perform ordinary relocations and shared-library loading. */
static int load_elf(const struct file_image *f, int interpreter, struct mapped *m,
                    struct error *e, uint64_t deadline) {
    const Elf64_Ehdr *h = (const void *)f->bytes;
    const Elf64_Phdr *ph;
    uint64_t low = UINT64_MAX, high = 0;
    int loads = 0, interps = 0, dynamic = 0, entry_ok = 0;
    unsigned char *perms = NULL;
    uintptr_t phdr_vaddr = 0;
    int phdr_found = 0;
    if (deadline_check(e, deadline))
        return -1;
    if (memcmp(h->e_ident, ELFMAG, SELFMAG) || h->e_ident[EI_CLASS] != ELFCLASS64 ||
        h->e_ident[EI_DATA] != ELFDATA2LSB || h->e_ident[EI_VERSION] != EV_CURRENT ||
        (h->e_ident[EI_OSABI] != ELFOSABI_NONE && h->e_ident[EI_OSABI] != ELFOSABI_LINUX) ||
        h->e_machine != EM_X86_64 || h->e_version != EV_CURRENT || h->e_flags ||
        h->e_ehsize != sizeof *h || h->e_phentsize != sizeof(Elf64_Phdr) || !h->e_phnum ||
        h->e_phnum > 128 || h->e_phoff > f->length ||
        h->e_phnum > (f->length - h->e_phoff) / sizeof(Elf64_Phdr) || h->e_type != ET_DYN)
        return fail(e, ST_ELF, ENOEXEC, 1);
    ph = (const void *)(f->bytes + h->e_phoff);
    for (unsigned i = 0; i < h->e_phnum; i++) {
        if (deadline_check(e, deadline))
            return -1;
        const Elf64_Phdr *p = &ph[i];
        if (p->p_offset > f->length || p->p_filesz > f->length - p->p_offset)
            return fail(e, ST_ELF, ENOEXEC, 1);
        if (p->p_type == PT_INTERP) {
            if (interpreter || ++interps != 1 || p->p_filesz < 2 || p->p_filesz >= PATH_MAX)
                return fail(e, ST_INTERPRETER, ENOEXEC, 1);
            const char *s = (const char *)f->bytes + p->p_offset;
            if (s[0] != '/' || s[p->p_filesz - 1] || memchr(s, 0, p->p_filesz - 1))
                return fail(e, ST_INTERPRETER, ENOEXEC, 1);
            memcpy(m->interpreter, s, p->p_filesz);
        }
        if (p->p_type == PT_DYNAMIC)
            dynamic++;
        if (p->p_type == PT_GNU_STACK && (p->p_flags & PF_X))
            return fail(e, ST_ELF, ENOTSUP, 1);
        if (p->p_type != PT_LOAD)
            continue;
        if (!p->p_memsz || p->p_filesz > p->p_memsz || p->p_vaddr > UINTPTR_MAX - p->p_memsz ||
            p->p_vaddr + p->p_memsz > UINTPTR_MAX - 4095 || (p->p_flags & ~(PF_R | PF_W | PF_X)) ||
            (p->p_align > 1 &&
             (!is_power2(p->p_align) || (p->p_vaddr % p->p_align) != (p->p_offset % p->p_align))) ||
            (p->p_vaddr & 4095) != (p->p_offset & 4095))
            return fail(e, ST_ELF, ENOEXEC, 1);
        for (unsigned j = 0; j < i; j++)
            if (ph[j].p_type == PT_LOAD && p->p_vaddr < ph[j].p_vaddr + ph[j].p_memsz &&
                ph[j].p_vaddr < p->p_vaddr + p->p_memsz)
                return fail(e, ST_ELF, ENOTSUP, 1);
        uint64_t a = p->p_vaddr & ~(uint64_t)4095, b = page_up((size_t)(p->p_vaddr + p->p_memsz));
        if (a < low)
            low = a;
        if (b > high)
            high = b;
        loads++;
        if ((p->p_flags & PF_X) && range_inside(h->e_entry, 1, p->p_vaddr, p->p_vaddr + p->p_memsz))
            entry_ok = 1;
        size_t phbytes = (size_t)h->e_phnum * sizeof(Elf64_Phdr);
        if (range_inside(h->e_phoff, phbytes, p->p_offset, p->p_offset + p->p_filesz)) {
            phdr_vaddr = p->p_vaddr + (h->e_phoff - p->p_offset);
            phdr_found = 1;
        }
    }
    if (!loads || !entry_ok || !phdr_found || dynamic != 1 || (!interpreter && interps != 1) ||
        low != 0 || high <= low || high - low > MAX_IMAGE)
        return fail(e, ST_ELF, ENOEXEC, 1);
    if (deadline_check(e, deadline))
        return -1;
    /* Reserve one anonymous image so its load bias is consistent. Anonymous
       pages supply ELF's zero-filled tail; segment bytes are copied before
       applying the final page permissions. Shared pages may combine flags,
       but any resulting writable/executable page is rejected below. */
    m->length = (size_t)(high - low);
    m->base = mmap(NULL, m->length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m->base == MAP_FAILED) {
        m->base = NULL;
        return fail(e, ST_MAP, errno, 0);
    }
    m->bias = (uintptr_t)m->base - (uintptr_t)low;
    m->entry = m->bias + h->e_entry;
    m->phdr = m->bias + phdr_vaddr;
    m->phnum = h->e_phnum;
    size_t np = m->length / 4096;
    perms = calloc(np, 1);
    if (!perms) {
        fail(e, ST_MAP, ENOMEM, 0);
        goto error;
    }
    for (unsigned i = 0; i < h->e_phnum; i++)
        if (ph[i].p_type == PT_LOAD) {
            if (deadline_check(e, deadline))
                goto error;
            const Elf64_Phdr *p = &ph[i];
            memcpy((void *)(m->bias + p->p_vaddr), f->bytes + p->p_offset, (size_t)p->p_filesz);
            int prot = ((p->p_flags & PF_R) ? PROT_READ : 0) |
                       ((p->p_flags & PF_W) ? PROT_WRITE : 0) |
                       ((p->p_flags & PF_X) ? PROT_EXEC : 0);
            size_t first = (size_t)((p->p_vaddr - low) / 4096),
                   end = (size_t)((page_up((size_t)(p->p_vaddr + p->p_memsz)) - low) / 4096);
            for (size_t j = first; j < end; j++)
                perms[j] |= (unsigned char)prot;
        }
    for (size_t i = 0; i < np; i++)
        if ((perms[i] & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
            fail(e, ST_ELF, ENOTSUP, 1);
            goto error;
        }
    for (size_t start = 0; start < np;) {
        if (deadline_check(e, deadline))
            goto error;
        size_t end = start + 1;
        while (end < np && perms[end] == perms[start])
            end++;
        if (mprotect((char *)m->base + start * 4096, (end - start) * 4096, perms[start])) {
            fail(e, ST_MAP, errno, 0);
            goto error;
        }
        start = end;
    }
    if (deadline_check(e, deadline))
        goto error;
    free(perms);
    return 0;
error:
    free(perms);
    munmap(m->base, m->length);
    memset(m, 0, sizeof *m);
    return -1;
}
void program_release(struct program *p) {
    if (p->exe.base)
        munmap(p->exe.base, p->exe.length);
    if (p->interp.base)
        munmap(p->interp.base, p->interp.length);
    if (p->stack_map)
        munmap(p->stack_map, p->stack_length);
    memset(p, 0, sizeof *p);
}
static uintptr_t put_string(uintptr_t *cursor, const char *s) {
    size_t n = strlen(s) + 1;
    *cursor -= n;
    memcpy((void *)*cursor, s, n);
    return *cursor;
}
/* Recreate the Linux x86-64 initial stack rather than call an ELF entry point
   as a C function. AT_BASE names the interpreter, while AT_ENTRY and AT_PHDR
   describe the main image. The inherited vDSO/hardware entries remain valid
   because clone preserves the address-space snapshot. */
static int prepare_stack(struct program *p, char **argv, int argc, struct error *e,
                         uint64_t deadline) {
    if (deadline_check(e, deadline))
        return -1;
    if (getauxval(AT_SECURE))
        return fail(e, ST_STACK, EPERM, 1);
    p->stack_length = STACK_BYTES + 8192;
    p->stack_map =
        mmap(NULL, p->stack_length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (p->stack_map == MAP_FAILED) {
        p->stack_map = NULL;
        return fail(e, ST_STACK, errno, 0);
    }
    void *body = (char *)p->stack_map + 4096;
    if (mprotect(body, STACK_BYTES, PROT_READ | PROT_WRITE))
        return fail(e, ST_STACK, errno, 0);
    uintptr_t cursor = (uintptr_t)body + STACK_BYTES, ap[MAX_ARGS], ep[3];
    const char *env[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"};
    for (int i = argc - 1; i >= 0; i--)
        ap[i] = put_string(&cursor, argv[i]);
    for (int i = 2; i >= 0; i--)
        ep[i] = put_string(&cursor, env[i]);
    const char *platform = (const char *)getauxval(AT_PLATFORM);
    uintptr_t platform_addr = 0;
    if (platform && strnlen(platform, 64) < 64)
        platform_addr = put_string(&cursor, platform);
    cursor -= 16;
    unsigned char random_bytes[16];
    ssize_t nr = getrandom(random_bytes, sizeof random_bytes, GRND_NONBLOCK);
    if (nr != sizeof random_bytes)
        return fail(e, ST_STACK, nr < 0 ? errno : EIO, 0);
    if (deadline_check(e, deadline))
        return -1;
    memcpy((void *)cursor, random_bytes, 16);
    uintptr_t random_addr = cursor;
    Elf64_auxv_t aux[32];
    size_t n = 0;
#define AUX(k, v)                                                                                  \
    do {                                                                                           \
        aux[n].a_type = (k);                                                                       \
        aux[n++].a_un.a_val = (Elf64_Addr)(v);                                                     \
    } while (0)
    AUX(AT_PHDR, p->exe.phdr);
    AUX(AT_PHENT, sizeof(Elf64_Phdr));
    AUX(AT_PHNUM, p->exe.phnum);
    AUX(AT_PAGESZ, 4096);
    AUX(AT_BASE, p->interp.bias);
    AUX(AT_FLAGS, 0);
    AUX(AT_ENTRY, p->exe.entry);
    AUX(AT_UID, getuid());
    AUX(AT_EUID, geteuid());
    AUX(AT_GID, getgid());
    AUX(AT_EGID, getegid());
    AUX(AT_SECURE, 0);
    AUX(AT_RANDOM, random_addr);
    AUX(AT_EXECFN, ap[0]);
    AUX(AT_HWCAP, getauxval(AT_HWCAP));
    AUX(AT_HWCAP2, getauxval(AT_HWCAP2));
    AUX(AT_CLKTCK, getauxval(AT_CLKTCK));
    AUX(AT_SYSINFO_EHDR, getauxval(AT_SYSINFO_EHDR));
    if (platform_addr)
        AUX(AT_PLATFORM, platform_addr);
#ifdef AT_MINSIGSTKSZ
    if (getauxval(AT_MINSIGSTKSZ))
        AUX(AT_MINSIGSTKSZ, getauxval(AT_MINSIGSTKSZ));
#endif
    AUX(AT_NULL, 0);
#undef AUX
    size_t words = 1 + (size_t)argc + 1 + 3 + 1 + n * 2;
    uintptr_t sp = (cursor - words * sizeof(uintptr_t)) & ~(uintptr_t)15;
    if (sp < (uintptr_t)body + 65536)
        return fail(e, ST_STACK, E2BIG, 1);
    uintptr_t *w = (uintptr_t *)sp;
    *w++ = (uintptr_t)argc;
    for (int i = 0; i < argc; i++)
        *w++ = ap[i];
    *w++ = 0;
    for (int i = 0; i < 3; i++)
        *w++ = ep[i];
    *w++ = 0;
    memcpy(w, aux, n * sizeof aux[0]);
    p->stack = sp;
    return deadline_check(e, deadline);
}
int program_prepare(char **argv, int argc, struct program *p, struct stat *identity,
                           struct error *e, uint64_t deadline) {
    struct file_image f = {0}, interp = {0};
    int rc = -1;
    if (file_read(argv[0], &f, e, deadline))
        goto done;
    *identity = f.identity;
    if (load_elf(&f, 0, &p->exe, e, deadline))
        goto done;
    if (file_read(p->exe.interpreter, &interp, e, deadline))
        goto done;
    if (load_elf(&interp, 1, &p->interp, e, deadline))
        goto done;
    if (prepare_stack(p, argv, argc, e, deadline))
        goto done;
    rc = 0;
done:
    file_release(&f);
    file_release(&interp);
    if (rc)
        program_release(p);
    return rc;
}
