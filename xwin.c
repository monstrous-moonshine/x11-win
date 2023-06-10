#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <X11/X.h>
#include <X11/Xproto.h>
#include <X11/Xauth.h>
#include "util.h"

#define X_CONNECTION_FAIL 0
#define X_CONNECTION_OKAY 1
#define X_CONNECTION_AUTH 2

void die(const char *msg) {
    perror(msg);
    exit(1);
}

void free_x_header(struct x_header *x_conn) {
    if (x_conn->status != X_CONNECTION_OKAY) {
        free(x_conn->fail.reason);
    } else {
        free(x_conn->pass.vendor);
        free(x_conn->pass.pixmap_formats);
        for (uint8_t i = 0; i < x_conn->pass.num_screen; i++) {
            for (uint8_t j = 0; j < x_conn->pass.roots[i].num_depth; j++) {
                free(x_conn->pass.roots[i].depths[j].visuals);
            }
            free(x_conn->pass.roots[i].depths);
        }
        free(x_conn->pass.roots);
    }
}

uint16_t read_short(FILE *fp) {
    uint8_t buf[2];
    if (fread(buf, 1, 2, fp) != 2) {
        if (feof(fp)) {
            fprintf(stderr, "ERROR: end of file\n");
            exit(1);
        } else {
            die("fread");
        }
    }
    return (buf[0] << 8) | buf[1];
}

int read_magic_cookie(char *dest, int dest_size) {
    int ret = 0;
    char xauth_fname[256];
    snprintf(xauth_fname, 256, "%s/.Xauthority", getenv("HOME"));
    FILE *fp = fopen(xauth_fname, "rb");
    if (!fp) {
        fprintf(stderr, "ERROR: can't open Xauthority file\n");
        exit(1);
    }
    fseek(fp, 0, SEEK_END);
    ssize_t fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* The Xauthority file contains entries of the following form:
     *
     * struct xauth_entry {
     *   uint16_t family;
     *   uint16_t addr_len;
     *   char     addr[addr_len];
     *   uint16_t num_len;
     *   char     num[num_len];
     *   uint16_t name_len;
     *   char     name[name_len];
     *   uint16_t data_len;
     *   char     data[data_len];
     * };
     *
     * Here, we only check if the family is FamilyLocal. We assume
     * the name is "MIT-MAGIC-COOKIE-1", and ignore the address and
     * the display number. If the family matches, we read the cookie
     * data into the dest buffer. In future, we probably should at
     * least check the protocol name too.
     */
    while (ftell(fp) < fsize) {
        uint16_t family = read_short(fp);
        uint16_t addr_len = read_short(fp);
        fseek(fp, addr_len, SEEK_CUR);
        uint16_t num_len = read_short(fp);
        fseek(fp, num_len, SEEK_CUR);
        uint16_t name_len = read_short(fp);
        fseek(fp, name_len, SEEK_CUR);
        uint16_t data_len = read_short(fp);
        if (family == FamilyLocal) {
            assert(data_len <= dest_size);
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
        char byte_order;
        char pad_1;
        uint16_t version_major;
        uint16_t version_minor;
        uint16_t len_auth_proto_name;
        uint16_t len_auth_proto_data;
        uint16_t pad_2;
        char auth_proto_name[20];
        char auth_proto_data[16];
    } __attribute__((packed)) header = {
        .byte_order = 'l',
        .version_major = 11,
        .version_minor = 0,
        .len_auth_proto_name = 18,
        .len_auth_proto_data = 16,
        .auth_proto_name = "MIT-MAGIC-COOKIE-1",
    };

    static_assert(sizeof(header) == 48, "wrong size for header");

    if (!read_magic_cookie(header.auth_proto_data, 16)) {
        fprintf(stderr, "ERROR: can't read cookie from Xauthority file\n");
        exit(1);
    }

    if (write(xfd, &header, sizeof(header)) != sizeof(header))
        die("write");

    if (read(xfd, x_conn, 8) != 8)
        die("read");

    if (x_conn->status != X_CONNECTION_OKAY) {
        if (!(x_conn->fail.reason = malloc(x_conn->length * 4)))
            die("malloc");
        if (read(xfd, x_conn->fail.reason, x_conn->length * 4) != x_conn->length * 4)
            die("read");
        return;
    }

    if (read(xfd, &x_conn->pass, 32) != 32)
        die("read");

    int vendor_len = (x_conn->pass.vendor_len + 3) / 4 * 4;
    if (!(x_conn->pass.vendor = malloc(vendor_len)))
        die("malloc");

    if (read(xfd, x_conn->pass.vendor, vendor_len) != vendor_len)
        die("read");

    int px_fmt_len = x_conn->pass.num_pixmap_format * sizeof(struct pixmap_format);
    if (!(x_conn->pass.pixmap_formats = malloc(px_fmt_len)))
        die("malloc");

    if (read(xfd, x_conn->pass.pixmap_formats, px_fmt_len) != px_fmt_len)
        die("read");

    int screen_len = x_conn->pass.num_screen * sizeof(struct x_screen);
    if (!(x_conn->pass.roots = malloc(screen_len)))
        die("malloc");

    for (uint8_t i = 0; i < x_conn->pass.num_screen; i++) {
        if (read(xfd, &x_conn->pass.roots[i], sizeof(struct x_screen) - 8)
                != sizeof(struct x_screen) - 8)
            die("read");

        int depths_len = x_conn->pass.roots[i].num_depth * sizeof(struct x_depth);
        if (!(x_conn->pass.roots[i].depths = malloc(depths_len)))
            die("malloc");

        for (uint8_t j = 0; j < x_conn->pass.roots[i].num_depth; j++) {
            if (read(xfd, &x_conn->pass.roots[i].depths[j], sizeof(struct x_depth) - 8)
                    != sizeof(struct x_depth) - 8)
                die("read");

            int visual_len = x_conn->pass.roots[i].depths[j].num_visual * sizeof(struct x_visual);
            if (!(x_conn->pass.roots[i].depths[j].visuals = malloc(visual_len)))
                die("malloc");

            if (read(xfd, x_conn->pass.roots[i].depths[j].visuals, visual_len) != visual_len)
                die("read");
        }
    }
}

void x_create_window(int xfd, struct x_header *x_conn) {
    uint32_t wid = x_conn->pass.resource_id_base;
    struct x_screen *screen = &x_conn->pass.roots[0];
    struct {
        uint8_t opcode;
        uint8_t depth;
        uint16_t req_len;
        uint32_t wid;
        uint32_t parent;
        int16_t x, y;
        uint16_t width, height;
        uint16_t border_width;
        uint16_t window_class;
        uint32_t visual;
        uint32_t attr_mask;
        uint32_t attr_list[2];
    } req_create_window = {
        .opcode = X_CreateWindow,
        .depth = CopyFromParent,
        .req_len = 10,
        .wid = wid,
        .parent = screen->root,
        .x = 0, .y = 0,
        .width = 150, .height = 150,
        .border_width = 0,
        .window_class = InputOutput,
        .visual = screen->root_visual,
        .attr_mask = CWBackPixel | CWEventMask,
        .attr_list = { screen->white_pixel, KeyReleaseMask },
    };

    if (write(xfd, &req_create_window, sizeof req_create_window) != sizeof req_create_window)
        die("write");
}

void x_map_window(int xfd, struct x_header *x_conn) {
    uint32_t wid = x_conn->pass.resource_id_base;
    struct {
        uint8_t opcode;
        uint8_t pad_1;
        uint16_t req_len;
        uint32_t window;
    } req_map_window = {
        .opcode = X_MapWindow,
        .req_len = 2,
        .window = wid,
    };

    if (write(xfd, &req_map_window, sizeof req_map_window) != sizeof req_map_window)
        die("write");
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
        fprintf(stderr, "ERROR: can't connect to X server (%d): %.*s\n", x_conn.status,
                x_conn.reason_len, x_conn.fail.reason);
        free_x_header(&x_conn);
        exit(1);
    }

    x_create_window(xfd, &x_conn);
    x_map_window(xfd, &x_conn);
    sleep(2);
    free_x_header(&x_conn);
}
