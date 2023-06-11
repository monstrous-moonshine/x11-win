#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <X11/X.h>
#include <X11/Xatom.h>
#include <X11/Xauth.h>
#include <X11/Xproto.h>
#include "util.h"

#define X_CONNECTION_FAIL 0
#define X_CONNECTION_OKAY 1
#define X_CONNECTION_AUTH 2

#define Write(fd, buf, n) ({                      \
        if (write(fd, buf, n) != n) die("write"); \
    })
#define Read(fd, buf, n) ({                       \
        if (read(fd, buf, n) != n) die("read");   \
    })
#define Malloc(n) ({                              \
        void *p = malloc(n);                      \
        if (!p) die("malloc");                    \
        p;                                        \
    })

void die(const char *msg) {
    perror(msg);
    exit(1);
}

void free_x_header(struct x_header *x_conn) {
    free(x_conn->vendor);
    free(x_conn->pixmap_formats);
    for (uint8_t i = 0; i < x_conn->num_screen; i++) {
        for (uint8_t j = 0; j < x_conn->roots[i].num_depth; j++) {
            free(x_conn->roots[i].depths[j].visuals);
        }
        free(x_conn->roots[i].depths);
    }
    free(x_conn->roots);
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
        .version_major = X_PROTOCOL,
        .version_minor = X_PROTOCOL_REVISION,
        .len_auth_proto_name = 18,
        .len_auth_proto_data = 16,
        .auth_proto_name = "MIT-MAGIC-COOKIE-1",
    };

    static_assert(sizeof(header) == 48, "wrong size for header");

    if (!read_magic_cookie(header.auth_proto_data, 16)) {
        fprintf(stderr, "ERROR: can't read cookie from Xauthority file\n");
        exit(1);
    }

    Write(xfd, &header, sizeof header);

    struct x_header_prefix x_conn_prefix;
    Read(xfd, &x_conn_prefix, sizeof x_conn_prefix);

    if (x_conn_prefix.status != X_CONNECTION_OKAY) {
        char *reason = Malloc(x_conn_prefix.length * 4);
        Read(xfd, reason, x_conn_prefix.length * 4);
        fprintf(stderr, "ERROR: can't connect to X server (%d): %.*s\n", x_conn_prefix.status,
                x_conn_prefix.reason_len, reason);
        free(reason);
        exit(1);
    }

    Read(xfd, x_conn, 32);

    int vendor_len = (x_conn->vendor_len + 3) / 4 * 4;
    x_conn->vendor = Malloc(vendor_len);
    Read(xfd, x_conn->vendor, vendor_len);

    int px_fmt_len = x_conn->num_pixmap_format * sizeof(struct pixmap_format);
    x_conn->pixmap_formats = Malloc(px_fmt_len);
    Read(xfd, x_conn->pixmap_formats, px_fmt_len);

    int screen_len = x_conn->num_screen * sizeof(struct x_screen);
    x_conn->roots = Malloc(screen_len);

    for (uint8_t i = 0; i < x_conn->num_screen; i++) {
        Read(xfd, &x_conn->roots[i], sizeof(struct x_screen) - 8);

        int depths_len = x_conn->roots[i].num_depth * sizeof(struct x_depth);
        x_conn->roots[i].depths = Malloc(depths_len);

        for (uint8_t j = 0; j < x_conn->roots[i].num_depth; j++) {
            Read(xfd, &x_conn->roots[i].depths[j], sizeof(struct x_depth) - 8);

            int visual_len = x_conn->roots[i].depths[j].num_visual * sizeof(struct x_visual);
            x_conn->roots[i].depths[j].visuals = Malloc(visual_len);

            Read(xfd, x_conn->roots[i].depths[j].visuals, visual_len);
        }
    }
}

void x_create_window(int xfd, struct x_header *x_conn) {
    uint32_t wid = x_conn->resource_id_base;
    struct x_screen *screen = &x_conn->roots[0];
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
        .attr_list = { screen->white_pixel, PointerMotionMask | KeyReleaseMask },
    };

    Write(xfd, &req_create_window, sizeof req_create_window);
}

void x_map_window(int xfd, struct x_header *x_conn) {
    uint32_t wid = x_conn->resource_id_base;
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

    Write(xfd, &req_map_window, sizeof req_map_window);
}

uint32_t x_intern_atom(int xfd, const char *atom) {
    int atom_len = strlen(atom);
    int atom_len_padded = (atom_len + 3) / 4 * 4;
    char pad[3];
    struct {
        uint8_t opcode;
        uint8_t only_if_exists;
        uint16_t req_len;
        uint16_t name_len;
        uint16_t pad_1;
    } req_intern_atom = {
        .opcode = X_InternAtom,
        .only_if_exists = 0,
        .req_len = 2 + atom_len_padded / 4,
        .name_len = atom_len,
    };

    Write(xfd, &req_intern_atom, sizeof req_intern_atom);
    Write(xfd, atom, atom_len);
    Write(xfd, pad, atom_len_padded - atom_len);

    struct {
        uint8_t type;
        uint8_t pad_1;
        uint16_t seq_num;
        uint32_t length;
        uint32_t atom;
        uint32_t pad_2[5];
    } x_reply;

    Read(xfd, &x_reply, sizeof x_reply);
    return x_reply.atom;
}

void x_change_property(int xfd, struct x_header *x_conn) {
    uint32_t wid = x_conn->resource_id_base;
    const char title[12] = "Hello, X11!";
    struct {
        uint8_t opcode;
        uint8_t mode;
        uint16_t req_len;
        uint32_t window;
        uint32_t property;
        uint32_t type;
        uint8_t format;
        uint8_t pad_1[3];
        uint32_t data_len;
        uint8_t data[12];
    } req_change_property = {
        .opcode = X_ChangeProperty,
        .mode = PropModeReplace,
        .req_len = 6 + sizeof title / 4,
        .window = wid,
        /* actually, it's a predefined atom (XA_WM_NAME), but
         * we intern it here to practice another protocol request
         * (one with a reply no less)
         */
        .property = x_intern_atom(xfd, "WM_NAME"),
        .type = XA_STRING, /* "STRING" */
        .format = 8,
        .data_len = strlen(title),
    };
    strncpy((char *)req_change_property.data, title, sizeof title);

    Write(xfd, &req_change_property, sizeof req_change_property);
}

int x_read_event(int xfd) {
    struct {
        char type;
        char data_1;
        uint16_t seq_num;
        uint32_t length;
        uint32_t data_2[6];
    } x_reply;

    int nread = read(xfd, &x_reply, sizeof x_reply);
    if (nread != sizeof x_reply) {
        /* check if there was an error, or we were interrupted by a signal */
        if (nread == -1)
            die("read");
        else
            return 1;
    }

    switch (x_reply.type) {
    case X_Error:
        printf("ERROR: error_code = %d\n", x_reply.data_1);
        return 1;
    case KeyRelease:
        // check for escape
        // keycodes are defined in /usr/include/linux/input-event-codes.h
        // Xorg keycodes are 8 larger than linux keycodes
        if (x_reply.data_1 == 9)
            return 1;
        break;
    case MotionNotify: {
        // as an example of handling another event, let's print pointer
        // coordinates on movement
        struct x_key_button_ptr {
            uint32_t pad_1;
            uint32_t time;
            uint32_t root, event, child;
            uint16_t root_x, root_y, event_x, event_y;
            uint16_t state;
            uint8_t  same_screen;
            uint8_t  pad_2;
        } *ev = (struct x_key_button_ptr *)&x_reply;
        printf("\rx = %4d, y = %4d", ev->event_x, ev->event_y);
        fflush(stdout);
        break;
    }
    default:
        printf("INFO: received event, type = %d\n", x_reply.type);
        break;
    }
    return 0;
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
    x_create_window(xfd, &x_conn);
    x_map_window(xfd, &x_conn);
    x_change_property(xfd, &x_conn);
    while (!x_read_event(xfd))
        ;
    free_x_header(&x_conn);
}
