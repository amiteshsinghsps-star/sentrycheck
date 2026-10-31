// An optional io_uring path followed by a deterministic, checked classic I/O path.
#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    struct io_uring_params parameters;
    memset(&parameters, 0, sizeof(parameters));
    int fd = (int)syscall(SYS_io_uring_setup, 8, &parameters);
    if (fd >= 0) close(fd);
    const char text[] = "classic-io-ok\n";
    return write(STDOUT_FILENO, text, sizeof(text)-1) == sizeof(text)-1 ? 0 : 43;
}
