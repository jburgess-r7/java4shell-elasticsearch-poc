#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static int print_identity(pid_t child) {
    char path[80], line[4096], *state, *save = NULL;
    snprintf(path, sizeof path, "/proc/%ld/stat", (long)child);
    FILE *input = fopen(path, "r");
    if (!input || !fgets(line, sizeof line, input)) {
        if (input) fclose(input);
        return -1;
    }
    fclose(input);
    state = strrchr(line, ')');
    if (!state) return -1;
    char *field = strtok_r(state + 1, " ", &save);
    for (int i = 0; field && i < 19; ++i) field = strtok_r(NULL, " ", &save);
    if (!field) return -1;
    printf("%ld:%s\n", (long)child, field);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "marker") == 0) {
        int fd = open(argv[2], O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (fd < 0) return 2;
        int ok = write(fd, "launched\n", 9) == 9;
        close(fd);
        return ok ? 0 : 3;
    }
    if (argc != 2) return 4;
    int count = atoi(argv[1]);
    if (count < 1 || count > 16) return 5;
    for (int i = 0; i < count; ++i) {
        pid_t child = fork();
        if (child < 0) return 6;
        if (child == 0) {
            close(0); close(1); close(2);
            for (;;) pause();
        }
        if (print_identity(child)) return 7;
    }
    return fflush(stdout) == 0 ? 0 : 8;
}
