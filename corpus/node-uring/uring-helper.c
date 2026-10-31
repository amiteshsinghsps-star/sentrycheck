// Real file I/O through liburing. Invoked by the Node workload, not a claim
// about which backend a particular Node/libuv release selects automatically.
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int complete(struct io_uring *ring, int expected) {
    struct io_uring_cqe *cqe = NULL;
    int submitted = io_uring_submit(ring);
    if (submitted != 1 || io_uring_wait_cqe(ring, &cqe) < 0) return 70;
    int result = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    if (result != expected) {
        fprintf(stderr, "unexpected io_uring completion: %d (expected %d)\n", result, expected);
        return 70;
    }
    return 0;
}

int main(void) {
    struct io_uring ring;
    int result = io_uring_queue_init(8, &ring, 0);
    if (result < 0) {
        fprintf(stderr, "required io_uring setup failed: %s\n", strerror(-result));
        return 42;
    }
    const char *path = "/tmp/sentrycheck-node-uring.txt";
    const char message[] = "sentrycheck-node-uring-verified";
    char readback[sizeof(message)] = {0};
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) { perror("open"); io_uring_queue_exit(&ring); return 70; }
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (!sqe) { close(fd); io_uring_queue_exit(&ring); return 70; }
    io_uring_prep_write(sqe, fd, message, sizeof(message), 0);
    result = complete(&ring, sizeof(message));
    if (!result) {
        sqe = io_uring_get_sqe(&ring);
        if (!sqe) result = 70;
        else {
            io_uring_prep_read(sqe, fd, readback, sizeof(readback), 0);
            result = complete(&ring, sizeof(readback));
            if (!result && memcmp(readback, message, sizeof(message))) result = 70;
        }
    }
    close(fd);
    unlink(path);
    io_uring_queue_exit(&ring);
    if (!result) puts(message);
    return result;
}
