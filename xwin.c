#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "util.h"

#define X_CONNECTION_FAIL 0
#define X_CONNECTION_OKAY 1
#define X_CONNECTION_AUTH 2

void die(const char *msg) {
    perror(msg);
    exit(1);
}

uint16_t read_short(FILE *fp) {
    uint8_t buf[2];
    if (fread(buf, 1, 2, fp) != 2)
        die("fread");
    return (buf[0] << 8) | buf[1];
}

int read_magic_cookie(char *dest) {
    int ret = 0;
    char xauth_fname[256];
    sprintf(xauth_fname, "%s/.Xauthority", getenv("HOME"));
    FILE *fp = fopen(xauth_fname, "rb");
    if (!fp) {
        fprintf(stderr, "ERROR: can't open Xauthority file\n");
        exit(1);
    }
    while (!feof(fp)) {
        uint16_t family = read_short(fp);
        uint16_t addr_len = read_short(fp);
        fseek(fp, addr_len, SEEK_CUR);
        uint16_t num_len = read_short(fp);
        fseek(fp, num_len, SEEK_CUR);
        uint16_t name_len = read_short(fp);
        fseek(fp, name_len, SEEK_CUR);
        uint16_t data_len = read_short(fp);
        if (family == 0x100) {
            fread(dest, 1, data_len, fp);
            ret = 1;
            break;
        } else {
            fseek(fp, data_len, SEEK_CUR);
        }
    }
    fclose(fp);
    return ret;
}

void x_connect(int xfd, struct x_header *x_conn) {
    struct {
        char byte_order[2];
        uint16_t version_major;
        uint16_t version_minor;
        uint16_t len_auth_proto_name;
        uint16_t len_auth_proto_data;
        char padding[2];
        char auth_proto_name[20];
        char auth_proto_data[16];
    } __attribute__((packed)) header = {
        .byte_order = { 'l' },
        .version_major = 11,
        .version_minor = 0,
        .len_auth_proto_name = 18,
        .len_auth_proto_data = 16,
        .auth_proto_name = "MIT-MAGIC-COOKIE-1",
    };

    static_assert(sizeof(header) == 48, "wrong size for header");

    if (!read_magic_cookie(header.auth_proto_data)) {
        fprintf(stderr, "ERROR: can't read cookie from Xauthority file\n");
        exit(1);
    }

    if (write(xfd, &header, sizeof(header)) != sizeof(header))
        die("write");

    if (read(xfd, x_conn, 8) != 8)
        die("read");

    if (x_conn->status != X_CONNECTION_OKAY) {
        x_conn->fail.reason = malloc(x_conn->length * 4);
        if (read(xfd, x_conn->fail.reason, x_conn->length * 4) != x_conn->length * 4)
            die("read");
        return;
    }
}

int main() {
    int xfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (xfd == -1)
        die("socket");
    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
        .sun_path = "/tmp/.X11-unix/X0",
    };
    if (connect(xfd, (const struct sockaddr *)&addr, sizeof(addr)) == -1)
        die("connect");
    struct x_header x_conn;
    x_connect(xfd, &x_conn);
    if (x_conn.status != X_CONNECTION_OKAY) {
        fprintf(stderr, "ERROR: can't connect to X server (%d): %s\n", x_conn.status, x_conn.fail.reason);
        free(x_conn.fail.reason);
        exit(1);
    }
}
