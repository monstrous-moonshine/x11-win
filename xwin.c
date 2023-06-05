#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

void die(const char *msg) {
    perror(msg);
    exit(1);
}

void x_connect(int xfd) {
    struct {
        char byte_order[2];
        uint16_t major;
        uint16_t minor;
        uint16_t len_name;
        uint16_t len_data;
        char padding[2];
    } __attribute__((packed)) header = {
        .byte_order = { 'l', '\0' },
        .major = 11,
        .minor = 6,
        .len_name = 0,
        .len_data = 0,
    };
    static_assert(sizeof(header) == 12, "wrong size for header");
    if (write(xfd, &header, sizeof(header)) != sizeof(header))
        die("write");

    char status;
    if (read(xfd, &status, 1) != 1)
        die("read");

    if (status == 0) {
        fprintf(stderr, "ERROR: can't connect to X server\n");
        exit(1);
    } else if (status == 2) {
        fprintf(stderr, "ERROR: further authentication required\n");
        exit(1);
    } else if (status != 1) {
        fprintf(stderr, "ERROR: illegal status received\n");
        exit(1);
    }
}

int main() {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1)
        die("socket");
    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
        .sun_path = "/tmp/.X11-unix/X0",
    };
    if (connect(sock_fd, (const struct sockaddr *)&addr, sizeof(addr)) == -1)
        die("connect");
}
