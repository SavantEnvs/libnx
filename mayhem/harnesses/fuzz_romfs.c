/*
 * fuzz_romfs — libnx RomFS mount + devoptab (nx/source/runtime/devices/romfs_dev.c).
 *
 * The input is a RomFS image. It is mounted through the public romfsMountFromFile() (or
 * romfsMountFromStorage(), chosen by the low bit of the last byte), exactly as a homebrew
 * mounts a RomFS read from an NRO / file / data storage. Every Horizon fs read is served from
 * the input by the fsFileRead()/fsStorageRead() stand-ins below (the IPC layer is not
 * available on a host). After mounting, the harness walks the whole tree through the
 * device's own devoptab callbacks (diropen/dirnext/dirclose, stat, open/read/seek/fstat,
 * chdir), and also tries the newline-separated paths in the input's tail. Unmounted at the
 * end of every input, so no state carries over.
 */
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/iosupport.h>
#include <sys/stat.h>
#include <switch/runtime/devices/romfs_dev.h>

static const uint8_t *g_data;
static size_t g_size;
static const devoptab_t *g_dev;

/* ---- environment stand-ins (kernel / IPC / newlib device table) ---- */
void *__libnx_alloc(size_t size) { return size > (64u << 20) ? NULL : malloc(size); }
void *__libnx_aligned_alloc(size_t a, size_t size) { (void)a; return __libnx_alloc(size); }
void __libnx_free(void *p) { free(p); }

static Result serve(s64 off, void *buf, u64 size, u64 *out) {
    u64 n = 0;
    if (off >= 0 && (u64)off < g_size) {
        n = g_size - (u64)off;
        if (n > size) n = size;
        memcpy(buf, g_data + off, n);
    }
    if (out) *out = n;
    return 0;
}
Result fsFileRead(FsFile *f, s64 off, void *buf, u64 size, u32 option, u64 *out) {
    (void)f; (void)option; return serve(off, buf, size, out);
}
void fsFileClose(FsFile *f) { (void)f; }
Result fsStorageRead(FsStorage *s, s64 off, void *buf, u64 size) {
    (void)s;
    u64 got = 0;
    serve(off, buf, size, &got);
    return got == size ? 0 : MAKERESULT(Module_Libnx, LibnxError_IoError);
}
void fsStorageClose(FsStorage *s) { (void)s; }
Result fsFsOpenFile(FsFileSystem *fs, const char *path, u32 mode, FsFile *out) {
    (void)fs; (void)path; (void)mode; (void)out; return MAKERESULT(Module_Libnx, LibnxError_NotFound);
}
Result fsOpenDataStorageByCurrentProcess(FsStorage *out) { (void)out; return MAKERESULT(Module_Libnx, LibnxError_NotFound); }
Result fsOpenDataStorageByProgramId(FsStorage *out, u64 id) { (void)out; (void)id; return MAKERESULT(Module_Libnx, LibnxError_NotFound); }
Result fsOpenDataStorageByDataId(FsStorage *out, u64 id, NcmStorageId sid) { (void)out; (void)id; (void)sid; return MAKERESULT(Module_Libnx, LibnxError_NotFound); }
int fsdevTranslatePath(const char *path, FsFileSystem **device, char *outpath) { (void)path; (void)device; (void)outpath; return -1; }
bool envIsNso(void) { return false; }
int __system_argc = 0;
char **__system_argv = NULL;
int AddDevice(const devoptab_t *d) { g_dev = d; return 3; }
int RemoveDevice(const char *name) { (void)name; g_dev = NULL; return 0; }

/* ---- driving the device ---- */
#define MAX_ENTRIES 512
static int g_entries;

static void try_file(const char *path) {
    struct _reent r = { 0, g_dev->deviceData };
    struct stat st;
    g_dev->stat_r(&r, path, &st);
    void *fo = calloc(1, g_dev->structSize);
    if (g_dev->open_r(&r, fo, path, O_RDONLY, 0) == 0) {
        char buf[4096];
        g_dev->fstat_r(&r, fo, &st);
        for (int i = 0; i < 64 && g_dev->read_r(&r, fo, buf, sizeof buf) > 0; i++) {}
        g_dev->seek_r(&r, fo, -16, SEEK_END);
        g_dev->read_r(&r, fo, buf, 32);
        g_dev->seek_r(&r, fo, 1, SEEK_SET);
        g_dev->read_r(&r, fo, buf, 7);
        g_dev->close_r(&r, fo);
    }
    free(fo);
}

static void walk(const char *path, int depth) {
    struct _reent r = { 0, g_dev->deviceData };
    DIR_ITER it = { 3, calloc(1, g_dev->dirStateSize) };
    if (g_dev->diropen_r(&r, &it, path)) {
        char name[NAME_MAX + 1];
        struct stat st;
        while (g_entries++ < MAX_ENTRIES && g_dev->dirnext_r(&r, &it, name, &st) == 0) {
            char child[2 * NAME_MAX];
            snprintf(child, sizeof child, "%s%s%s", path, path[strlen(path) - 1] == '/' ? "" : "/", name);
            if (S_ISDIR(st.st_mode)) {
                if (depth < 8) walk(child, depth + 1);
            } else {
                try_file(child);
            }
        }
        g_dev->dirreset_r(&r, &it);
        g_dev->dirnext_r(&r, &it, name, &st);
        g_dev->dirclose_r(&r, &it);
    }
    free(it.dirStruct);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    g_data = data;
    g_size = size;
    g_entries = 0;
    uint8_t ctl = data[size - 1];
    Result rc;
    if (ctl & 1) {
        FsStorage s; memset(&s, 0, sizeof s);
        rc = romfsMountFromStorage(s, 0, "fz");
    } else {
        FsFile f; memset(&f, 0, sizeof f);
        rc = romfsMountFromFile(f, 0, "fz");
    }
    if (R_FAILED(rc) || !g_dev) return 0;

    walk("fz:/", 0);

    /* Paths from the input tail: up to (ctl >> 1) bytes before the control byte. */
    size_t plen = ctl >> 1;
    if (plen > size - 1) plen = size - 1;
    char *paths = malloc(plen + 1);
    memcpy(paths, data + size - 1 - plen, plen);
    paths[plen] = 0;
    for (char *save = NULL, *p = strtok_r(paths, "\n", &save); p; p = strtok_r(NULL, "\n", &save)) {
        struct _reent r = { 0, g_dev->deviceData };
        try_file(p);
        walk(p, 6);
        g_dev->chdir_r(&r, p);
        try_file("x");
    }
    free(paths);
    romfsUnmount("fz");
    return 0;
}
