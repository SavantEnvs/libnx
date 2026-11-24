/*
 * fuzz_utf — libnx UTF converters (nx/source/runtime/util/utf/*.c).
 * The first byte picks the source encoding (UTF-8 / UTF-16 / UTF-32); the rest is a
 * NUL-terminated string in that encoding. Each converter is called the documented way:
 * once with out=NULL to size the result, then into a buffer of exactly that size, then the
 * result is converted back (round trip) and the streaming decode_* helpers walk the input.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <switch/runtime/util/utf.h>

static void *dup_nul(const uint8_t *d, size_t n, size_t unit, size_t *count) {
    *count = n / unit;
    uint8_t *p = calloc(*count + 1, unit);
    memcpy(p, d, *count * unit);
    return p;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    uint8_t sel = data[0];
    data++; size--;
    size_t n;
    switch (sel % 3) {
    case 0: {
        uint8_t *in = dup_nul(data, size, 1, &n);
        ssize_t l16 = utf8_to_utf16(NULL, in, 0), l32 = utf8_to_utf32(NULL, in, 0);
        if (l16 >= 0) {
            uint16_t *o = calloc(l16 + 1, 2);
            utf8_to_utf16(o, in, l16);
            ssize_t back = utf16_to_utf8(NULL, o, 0);
            if (back >= 0) { uint8_t *b = calloc(back + 1, 1); utf16_to_utf8(b, o, back); free(b); }
            free(o);
        }
        if (l32 >= 0) {
            uint32_t *o = calloc(l32 + 1, 4);
            utf8_to_utf32(o, in, l32);
            ssize_t back = utf32_to_utf8(NULL, o, 0);
            if (back >= 0) { uint8_t *b = calloc(back + 1, 1); utf32_to_utf8(b, o, back); free(b); }
            free(o);
        }
        /* Truncated outputs, as callers with a fixed buffer do. */
        uint16_t small16[8]; uint32_t small32[8];
        utf8_to_utf16(small16, in, sel % 8);
        utf8_to_utf32(small32, in, (sel >> 3) % 8);
        for (const uint8_t *p = in; *p;) { uint32_t c; ssize_t u = decode_utf8(&c, p); if (u < 0) break; p += u; }
        free(in);
        break;
    }
    case 1: {
        uint16_t *in = dup_nul(data, size, 2, &n);
        ssize_t l8 = utf16_to_utf8(NULL, in, 0), l32 = utf16_to_utf32(NULL, in, 0);
        if (l8 >= 0) {
            uint8_t *o = calloc(l8 + 1, 1);
            utf16_to_utf8(o, in, l8);
            ssize_t back = utf8_to_utf16(NULL, o, 0);
            if (back >= 0) { uint16_t *b = calloc(back + 1, 2); utf8_to_utf16(b, o, back); free(b); }
            free(o);
        }
        if (l32 >= 0) {
            uint32_t *o = calloc(l32 + 1, 4);
            utf16_to_utf32(o, in, l32);
            ssize_t back = utf32_to_utf16(NULL, o, 0);
            if (back >= 0) { uint16_t *b = calloc(back + 1, 2); utf32_to_utf16(b, o, back); free(b); }
            free(o);
        }
        uint8_t small8[8];
        utf16_to_utf8(small8, in, (sel >> 2) % 8);
        for (const uint16_t *p = in; *p;) { uint32_t c; ssize_t u = decode_utf16(&c, p); if (u < 0) break; p += u; }
        free(in);
        break;
    }
    default: {
        uint32_t *in = dup_nul(data, size, 4, &n);
        ssize_t l8 = utf32_to_utf8(NULL, in, 0), l16 = utf32_to_utf16(NULL, in, 0);
        if (l8 >= 0) { uint8_t *o = calloc(l8 + 1, 1); utf32_to_utf8(o, in, l8); free(o); }
        if (l16 >= 0) { uint16_t *o = calloc(l16 + 1, 2); utf32_to_utf16(o, in, l16); free(o); }
        uint8_t e8[4]; uint16_t e16[2];
        for (size_t i = 0; i < n; i++) { encode_utf8(e8, in[i]); encode_utf16(e16, in[i]); }
        free(in);
        break;
    }
    }
    return 0;
}
