#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

struct x_header {
    uint8_t status;
    uint8_t pad_1[1];
    uint16_t version_major;
    uint16_t version_minor;
    uint16_t length;
    union {
        struct {
            char *reason;
        } fail;
        struct {
            uint32_t release_num;
            uint32_t resource_id_base;
            uint32_t resource_id_mask;
            uint32_t motion_buf_size;
            uint16_t vendor_len;
            uint16_t max_request_len;
            uint8_t num_screen;
            uint8_t num_pixmap_format;
            uint8_t image_byte_order;
            uint8_t bitmap_bit_order;
            uint8_t bitmap_scanline_unit;
            uint8_t bitmap_scanline_pad;
            uint8_t min_keycode;
            uint8_t max_keycode;
            uint8_t pad_1[4];
        } pass;
    };
} __attribute__((packed));

static_assert(sizeof(struct x_header) == 40, "wrong size for header");

#endif
