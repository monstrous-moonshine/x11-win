# x11-win
Opening a window using the raw X11 protocol

This project is inspired by this [blog post](https://gaultier.github.io/blog/x11_x64.html), where the author opens a window by talking directly to the X server (without using xlib or xcb). In that post, the author does it in x64 assembly for fun. Here, I wanted to focus on learning the X11 protocol, so I did it in C.

To compile it, you'll need the X11 development headers. Move your mouse over the window to see the pointer coordinates change. To quit, press escape.

The X11 protocol is documented in detail at [x.org](https://www.x.org/releases/X11R7.7/doc/xproto/x11protocol.html). The header files under `/usr/include/X11`, especially `X.h` and `Xproto.h`, also contain a lot of interesting information.

I don't think there's much else to say about it. It was a lot of fun!
