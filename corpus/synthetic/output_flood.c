#include <unistd.h>

int main(void) {
    static char bytes[4096];
    for (int block = 0; block < 10240; ++block) {
        if (write(1, bytes, sizeof(bytes)) != sizeof(bytes)) return 1;
    }
    return 0;
}
