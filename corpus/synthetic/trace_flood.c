/* Synthetic capture-boundary regression, not a representative workload.
 * Each failed write produces a long, escaped strace record without sending any
 * bytes to stdout, stderr, the filesystem, or another process. The finite loop
 * generates roughly 64 MiB of guest trace unless the scanner stops it first. */
#include <errno.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    unsigned char bytes[256];
    memset(bytes, 0xff, sizeof(bytes));
    for (unsigned int record = 0; record < 65536; ++record) {
        errno = 0;
        if (write(-1, bytes, sizeof(bytes)) != -1 || errno != EBADF) return 3;
    }
    return 0;
}
