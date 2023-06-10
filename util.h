#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

struct pixmap_format {
    uint8_t depth;
    uint8_t bpp;
    uint8_t scanline_pad;
    uint8_t padding[5];
} __attribute__((packed));

struct x_visual {
    uint32_t visual_id;
    uint8_t visual_class;
    uint8_t bit_per_rgb_value;
    uint16_t colormap_entries;
    uint32_t red_mask;
    uint32_t green_mask;
    uint32_t blue_mask;
    uint8_t pad_1[4];
} __attribute__((packed));

struct x_depth {
    uint8_t depth;
    uint8_t pad_1[1];
    uint16_t num_visual;
    uint8_t pad_2[4];
    struct x_visual *visuals;
} __attribute__((packed));

struct x_screen {
    uint32_t root;
    uint32_t default_colormap;
    uint32_t white_pixel;
    uint32_t black_pixel;
    uint32_t current_input_masks;
    uint16_t width_px;
    uint16_t height_px;
    uint16_t width_mm;
    uint16_t height_mm;
    uint16_t min_installed_map;
    uint16_t max_installed_map;
    uint32_t root_visual;
    uint8_t  backing_stores;
    uint8_t  save_unders;
    uint8_t  root_depth;
    uint8_t  num_allowed_depth;
    struct x_depth *allowed_depths;
} __attribute__((packed));

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
            char *vendor;
            struct pixmap_format *pixmap_formats;
            struct x_screen *roots;
        } pass;
    };
} __attribute__((packed));

static_assert(sizeof(struct x_header) == 64, "wrong size for header");
static_assert(sizeof(struct x_screen) == 48, "wrong size for header");
static_assert(sizeof(struct x_depth) == 16, "wrong size for header");
static_assert(sizeof(struct x_visual) == 24, "wrong size for header");
static_assert(sizeof(struct pixmap_format) == 8, "wrong size for header");

#endif
