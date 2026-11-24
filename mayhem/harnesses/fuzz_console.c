/*
 * fuzz_console — libnx text console (nx/source/runtime/devices/console.c) with its real
 * software renderer (console_sw.c). The input is the byte stream a homebrew writes to
 * stdout: it goes through the console devoptab's write_r (con_write), i.e. the ANSI/VT100
 * escape-sequence parser (cursor movement, erase, SGR colours incl. 256-colour/RGB), and
 * consolePrintChar/NewRow/Cls drawing glyphs into the framebuffer.
 *
 * console.c is included into this TU so its parser state (the static escapeSeq) can be reset
 * before each input: the result of an input must not depend on the previous one. The
 * framebuffer and NWindow are host stand-ins: an exactly-sized heap buffer, so ASan catches
 * a glyph drawn outside it.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../../nx/source/runtime/devices/console.c"

const devoptab_t *devoptab_list[STD_MAX];

static u16 *g_fb;
static u32 g_w, g_h;
static NWindow g_win;

NWindow *nwindowGetDefault(void) { return &g_win; }
Result nwindowSetDimensions(NWindow *nw, u32 w, u32 h) { (void)nw; g_w = w; g_h = h; return 0; }
Result framebufferCreate(Framebuffer *fb, NWindow *win, u32 w, u32 h, u32 fmt, u32 n) {
    (void)fb; (void)win; (void)fmt; (void)n;
    free(g_fb);
    g_w = w; g_h = h;
    g_fb = calloc((size_t)w * h, sizeof(u16));
    return 0;
}
Result framebufferMakeLinear(Framebuffer *fb) { (void)fb; return 0; }
void framebufferClose(Framebuffer *fb) { (void)fb; }
void *framebufferBegin(Framebuffer *fb, u32 *out_stride) { (void)fb; *out_stride = g_w * sizeof(u16); return g_fb; }
void framebufferEnd(Framebuffer *fb) { (void)fb; }

static PrintConsole g_con;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    memset(&escapeSeq, 0, sizeof escapeSeq);
    escapeSeq.color.fg = 7;
    /* consoleInit clears and redraws the whole screen, so do it once; then reset everything an
     * input can change (window, cursor, colours, flags) to consoleInit's defaults. */
    static PrintConsole *c;
    if (!c) c = consoleInit(&g_con);
    if (!c) return 0;
    consoleSetWindow(c, 1, 1, c->consoleWidth, c->consoleHeight);
    c->prevCursorX = c->prevCursorY = 1;
    c->fg = 7; c->bg = 0; c->flags = 0;
    const devoptab_t *dev = __nx_get_console_dotab();
    struct _reent r = { 0, NULL };
    /* Split the stream in two writes, as stdio may: the parser must keep state across them. */
    size_t half = size / 2;
    dev->write_r(&r, NULL, (const char *)data, half);
    dev->write_r(&r, NULL, (const char *)data + half, size - half);
    consoleUpdate(c);
    return 0;
}
