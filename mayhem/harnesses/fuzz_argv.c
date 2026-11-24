/*
 * fuzz_argv — libnx argv tokenizer (argvSetup, nx/source/runtime/argv.c, plus nxlinkSetup from
 * nx/source/runtime/nxlink.c). The input is the argument string the homebrew loader passes
 * (envGetArgv()). argvSetup carves its 0x9000-byte argument area out of the newlib fake heap;
 * here the fake heap is an exactly-sized malloc so ASan sees any write past it.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <switch/types.h>
#include <switch/result.h>
#include <switch/kernel/svc.h>

void argvSetup(void);
extern int __system_argc;
extern char **__system_argv;

char *fake_heap_start;
char *fake_heap_end;
u8 __argdata__[0x20];
static char *g_args;

bool envIsNso(void) { return false; }
bool envHasArgv(void) { return true; }
char *envGetArgv(void) { return g_args; }
Result svcQueryMemory(MemoryInfo *mi, u32 *pi, u64 addr) { (void)mi; (void)pi; (void)addr; return 1; }

#define HEAP 0x9000

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    g_args = malloc(size + 1);
    memcpy(g_args, data, size);
    g_args[size] = 0;
    char *heap = malloc(HEAP);
    fake_heap_start = heap;
    fake_heap_end = heap + HEAP;
    argvSetup();
    size_t total = 0;
    for (int i = 0; i < __system_argc && __system_argv[i]; i++) total += strlen(__system_argv[i]);
    (void)total;
    free(heap);
    free(g_args);
    return 0;
}
