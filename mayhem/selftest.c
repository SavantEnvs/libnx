/*
 * libnx_selftest — known-answer functional tests for the libnx sources the fuzz targets cover
 * (UTF converters, inet_*, argv tokenizer, Parcel replies, RomFS mount/read, console escapes).
 * Built by mayhem/build.sh with normal flags; run by mayhem/test.sh with the RomFS sample image.
 * Prints one "PASS <name>" / "FAIL <name>" line per check and a final "RESULT <passed> <failed>".
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "../nx/source/runtime/devices/console.c"
#include <switch/runtime/util/utf.h>
#include <switch/runtime/devices/romfs_dev.h>
#include <switch/display/parcel.h>
#include <switch/kernel/svc.h>

static int passed, failed;
#define CHECK(name, cond) do { if (cond) { passed++; printf("PASS %s\n", name); } \
                               else { failed++; printf("FAIL %s\n", name); } } while (0)

/* ---------------- host stand-ins ---------------- */
const devoptab_t *devoptab_list[STD_MAX];
static const devoptab_t *g_dev;
int AddDevice(const devoptab_t *d) { g_dev = d; return 3; }
int RemoveDevice(const char *n) { (void)n; g_dev = NULL; return 0; }
void *__libnx_alloc(size_t s) { return malloc(s); }
void *__libnx_aligned_alloc(size_t a, size_t s) { (void)a; return malloc(s); }
void __libnx_free(void *p) { free(p); }

static uint8_t *g_img; static size_t g_img_size;
Result fsFileRead(FsFile *f, s64 off, void *buf, u64 size, u32 opt, u64 *out) {
    (void)f; (void)opt; u64 n = 0;
    if (off >= 0 && (u64)off < g_img_size) { n = g_img_size - off; if (n > size) n = size; memcpy(buf, g_img + off, n); }
    *out = n; return 0;
}
void fsFileClose(FsFile *f) { (void)f; }
Result fsStorageRead(FsStorage *s, s64 off, void *buf, u64 size) { u64 n; fsFileRead(NULL, off, buf, size, 0, &n); (void)s; return n == size ? 0 : 1; }
void fsStorageClose(FsStorage *s) { (void)s; }
Result fsFsOpenFile(FsFileSystem *fs, const char *p, u32 m, FsFile *o) { (void)fs; (void)p; (void)m; (void)o; return 1; }
Result fsOpenDataStorageByCurrentProcess(FsStorage *o) { (void)o; return 1; }
Result fsOpenDataStorageByProgramId(FsStorage *o, u64 i) { (void)o; (void)i; return 1; }
Result fsOpenDataStorageByDataId(FsStorage *o, u64 i, NcmStorageId s) { (void)o; (void)i; (void)s; return 1; }
int fsdevTranslatePath(const char *p, FsFileSystem **d, char *o) { (void)p; (void)d; (void)o; return -1; }

static char *g_args;
char *fake_heap_start, *fake_heap_end;
u8 __argdata__[0x20];
bool envIsNso(void) { return false; }
bool envHasArgv(void) { return true; }
char *envGetArgv(void) { return g_args; }
Result svcQueryMemory(MemoryInfo *mi, u32 *pi, u64 a) { (void)mi; (void)pi; (void)a; return 1; }
void argvSetup(void);
extern int __system_argc;
extern char **__system_argv;

static uint8_t g_reply[PARCEL_MAX_PAYLOAD]; static size_t g_reply_size;
Result binderTransactParcel(Binder *b, u32 c, void *in, size_t is, void *out, size_t os, u32 f) {
    (void)b; (void)c; (void)in; (void)is; (void)f; memcpy(out, g_reply, g_reply_size < os ? g_reply_size : os); return 0;
}

static u16 *g_fb; static u32 g_w, g_h; static NWindow g_win;
NWindow *nwindowGetDefault(void) { return &g_win; }
Result nwindowSetDimensions(NWindow *nw, u32 w, u32 h) { (void)nw; g_w = w; g_h = h; return 0; }
Result framebufferCreate(Framebuffer *fb, NWindow *win, u32 w, u32 h, u32 fmt, u32 n) { (void)fb; (void)win; (void)fmt; (void)n; g_w = w; g_h = h; g_fb = calloc((size_t)w * h, 2); return 0; }
Result framebufferMakeLinear(Framebuffer *fb) { (void)fb; return 0; }
void framebufferClose(Framebuffer *fb) { (void)fb; }
void *framebufferBegin(Framebuffer *fb, u32 *st) { (void)fb; *st = g_w * 2; return g_fb; }
void framebufferEnd(Framebuffer *fb) { (void)fb; }

int nx_inet_pton(int af, const char *src, void *dst);
const char *nx_inet_ntop(int af, const void *src, char *dst, socklen_t size);
int nx_inet_aton(const char *cp, struct in_addr *inp);
in_addr_t nx_inet_addr(const char *cp);

/* ---------------- tests ---------------- */
static void test_utf(void) {
    const uint8_t s[] = "h\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80";   /* h é € 😀 */
    uint16_t u16[16] = {0}; uint32_t u32[16] = {0}; uint8_t back[32] = {0};
    CHECK("utf8_to_utf16 size", utf8_to_utf16(NULL, s, 0) == 5);
    ssize_t n = utf8_to_utf16(u16, s, 16);
    CHECK("utf8_to_utf16 units", n == 5 && u16[0] == 'h' && u16[1] == 0xe9 && u16[2] == 0x20ac && u16[3] == 0xd83d && u16[4] == 0xde00);
    n = utf8_to_utf32(u32, s, 16);
    CHECK("utf8_to_utf32", n == 4 && u32[3] == 0x1f600);
    n = utf16_to_utf8(back, u16, sizeof back);
    CHECK("utf16_to_utf8 roundtrip", n == 10 && memcmp(back, s, 10) == 0);
    uint16_t bad[] = { 0xd800, 0x61, 0 };   /* high surrogate not followed by a low one */
    CHECK("utf16 lone surrogate rejected", utf16_to_utf8(back, bad, sizeof back) < 0);
    const uint8_t over[] = "\xc0\x80";
    CHECK("utf8 overlong rejected", utf8_to_utf32(u32, over, 16) < 0);
    memset(back, 0, sizeof back);
    n = utf32_to_utf8(back, u32, sizeof back);
    CHECK("utf32_to_utf8", n == 10 && memcmp(back, s, 10) == 0);
}

static void test_inet(void) {
    struct in_addr a; struct in6_addr a6; char buf[64];
    CHECK("inet_pton v4", nx_inet_pton(AF_INET, "192.168.1.20", &a) == 1 && ntohl(a.s_addr) == 0xc0a80114);
    CHECK("inet_pton v4 reject", nx_inet_pton(AF_INET, "256.1.1.1", &a) == 0);
    CHECK("inet_aton short form", nx_inet_aton("0x7f.1", &a) == 1 && ntohl(a.s_addr) == 0x7f000001);
    CHECK("inet_addr invalid", nx_inet_addr("not.an.ip") == INADDR_NONE);
    CHECK("inet_pton v6", nx_inet_pton(AF_INET6, "2001:db8::ff00:42:8329", &a6) == 1 &&
          a6.s6_addr[0] == 0x20 && a6.s6_addr[1] == 0x01 && a6.s6_addr[3] == 0xb8 && a6.s6_addr[15] == 0x29 && a6.s6_addr[13] == 0x42);
    memset(&a6, 0, sizeof a6);
    CHECK("inet_ntop v6 any", nx_inet_ntop(AF_INET6, &a6, buf, sizeof buf) && strcmp(buf, "::") == 0);
    CHECK("inet_ntop v6 small dst", nx_inet_ntop(AF_INET6, &a6, buf, 2) == NULL);
    CHECK("inet_ntop v4", nx_inet_ntop(AF_INET, &a, buf, sizeof buf) && strcmp(buf, "127.0.0.1") == 0);
    CHECK("inet_ntop small dst", nx_inet_ntop(AF_INET, &a, buf, 4) == NULL);
}

static void test_argv(void) {
    char *heap = malloc(0x9000);
    fake_heap_start = heap; fake_heap_end = heap + 0x9000;
    g_args = strdup("sdmc:/app.nro  \"two words\" last");
    argvSetup();
    CHECK("argv count", __system_argc == 3);
    CHECK("argv values", __system_argc == 3 && strcmp(__system_argv[0], "sdmc:/app.nro") == 0 &&
          strcmp(__system_argv[1], "two words") == 0 && strcmp(__system_argv[2], "last") == 0 && __system_argv[3] == NULL);
    free(g_args); free(heap);
}

static void test_parcel(void) {
    Binder b; memset(&b, 0, sizeof b);
    Parcel req, rep; parcelCreate(&req); parcelCreate(&rep);
    parcelWriteInterfaceToken(&req, "x");
    uint32_t r[] = { 16, 16, 0, 0, 7, 0xfffffffe, 4, 0, 0x41424344 };
    memset(g_reply, 0, sizeof g_reply); memcpy(g_reply, r, sizeof r); g_reply_size = sizeof r;
    CHECK("parcelTransact ok", parcelTransact(&b, 1, &req, &rep) == 0 && rep.payload_size == 16);
    CHECK("parcelReadInt32", parcelReadInt32(&rep) == 7 && parcelReadInt32(&rep) == -2);
    size_t sz = 0; void *p = parcelReadFlattenedObject(&rep, &sz);
    CHECK("parcelReadFlattenedObject", p == NULL && sz == 4);   /* only 16 payload bytes: object does not fit */
    uint32_t bad[] = { 0x100, 0x3f0, 0, 0 };
    memcpy(g_reply, bad, sizeof bad); g_reply_size = sizeof bad;
    CHECK("parcelTransact rejects oob", parcelTransact(&b, 1, &req, &rep) != 0);
}

static int read_file(const char *path, char *out, size_t cap) {
    struct _reent r = { 0, g_dev->deviceData };
    void *fo = calloc(1, g_dev->structSize);
    int n = -1;
    if (g_dev->open_r(&r, fo, path, O_RDONLY, 0) == 0) { n = (int)g_dev->read_r(&r, fo, out, cap); g_dev->close_r(&r, fo); }
    free(fo);
    return n;
}

static void test_romfs(const char *img) {
    FILE *f = fopen(img, "rb");
    if (!f) { CHECK("romfs sample present", 0); return; }
    g_img = malloc(1 << 16); g_img_size = fread(g_img, 1, 1 << 16, f); fclose(f);
    FsFile ff; memset(&ff, 0, sizeof ff);
    CHECK("romfsMountFromFile", romfsMountFromFile(ff, 0, "t") == 0 && g_dev);
    if (!g_dev) return;
    char buf[64] = {0};
    CHECK("romfs read sub/hello.txt", read_file("t:/sub/hello.txt", buf, sizeof buf) == 9 && memcmp(buf, "hi there\n", 9) == 0);
    memset(buf, 0, sizeof buf);
    CHECK("romfs read via ..", read_file("t:/sub/deep/../deep/x", buf, sizeof buf) == 6 && memcmp(buf, "nested", 6) == 0);
    struct _reent r = { 0, g_dev->deviceData }; struct stat st;
    CHECK("romfs stat size", g_dev->stat_r(&r, "t:/top.bin", &st) == 0 && st.st_size == 40 && S_ISREG(st.st_mode));
    CHECK("romfs missing", read_file("t:/sub/nope", buf, sizeof buf) < 0);
    DIR_ITER it = { 3, calloc(1, g_dev->dirStateSize) };
    int n = 0; char name[NAME_MAX + 1]; char seen[128] = "";
    if (g_dev->diropen_r(&r, &it, "t:/")) {
        while (g_dev->dirnext_r(&r, &it, name, &st) == 0) { n++; strcat(seen, name); strcat(seen, ","); }
        g_dev->dirclose_r(&r, &it);
    }
    free(it.dirStruct);
    CHECK("romfs readdir root", n == 4 && strcmp(seen, ".,..,sub,top.bin,") == 0);
    CHECK("romfsUnmount", romfsUnmount("t") == 0);
}

static void test_console(void) {
    PrintConsole con; memset(&con, 0, sizeof con);
    PrintConsole *c = consoleInit(&con);
    CHECK("consoleInit", c && c->consoleInitialised);
    if (!c) return;
    const devoptab_t *d = __nx_get_console_dotab();
    struct _reent r = { 0, NULL };
    const char s1[] = "AB\x1b[10;20HC";
    d->write_r(&r, NULL, s1, sizeof s1 - 1);
    CHECK("console CUP", c->cursorX == 21 && c->cursorY == 10);
    const char s2[] = "\x1b[3D\x1b[2A\x1b[31;1m";
    d->write_r(&r, NULL, s2, sizeof s2 - 1);
    CHECK("console CUB/CUU", c->cursorX == 18 && c->cursorY == 8);
    CHECK("console SGR", c->fg == 1 && (c->flags & CONSOLE_COLOR_BOLD));
    const char s3[] = "\n\tx";
    d->write_r(&r, NULL, s3, sizeof s3 - 1);
    CHECK("console newline/tab", c->cursorY == 9 && c->cursorX == 5);
}

int main(int argc, char **argv) {
    test_utf();
    test_inet();
    test_argv();
    test_parcel();
    test_romfs(argc > 1 ? argv[1] : "mayhem/romfs/testsuite/sample_file.romfs");
    test_console();
    printf("RESULT %d %d\n", passed, failed);
    return failed != 0;
}
