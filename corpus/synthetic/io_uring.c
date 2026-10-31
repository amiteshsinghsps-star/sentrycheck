// A deliberately required io_uring path. Exit 42 if setup fails, 0 if it works.
// Label as incompatible only when the native baseline succeeds for this host.
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
    if (fd < 0) { perror("io_uring_setup"); return 42; }
    close(fd);
    puts("io-uring-ok");
    return 0;
}
