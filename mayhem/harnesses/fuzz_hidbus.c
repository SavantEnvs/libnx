/*
 * fuzz_hidbus — libnx hidbus client (nx/source/services/hidbus.c), the code behind Joy-Con
 * rail devices (Ring-Con etc.). Reaches hidbusGetJoyPollingReceivedData(), changed by upstream
 * fix 0f38ec8a3d ("hidbus: Adjusted out-of-bounds size handling"), through the public call
 * sequence a homebrew uses: hidbusGetBusHandle -> hidbusInitialize -> hidbusEnableJoyPolling
 * ReceiveMode -> hidbusGetJoyPollingReceivedData -> hidbusDisableJoyPollingReceiveMode ->
 * hidbusFinalize.
 *
 * Untrusted data here is what the hidbus sysmodule hands back: IPC replies, the hidbus shared
 * memory (status manager) and the polling ring the sysmodule writes into the caller's
 * transfer-memory work buffer. All three come from the input:
 *   byte 0      HOS version (5.0/6.0/8.0/10.0), byte 1: polling mode, byte 2: count
 *   8 x 16 B    IPC reply payloads, in call order (first u32 0xffffffff = fail that call)
 *   workbuf     WORKBUF_SIZE bytes (the polling ring; the largest of the three accessors)
 *   rest        hidbus shared memory (0x1000 bytes, zero-padded)
 * The fake sysmodule (svcSendSyncRequest below) answers each CMIF request in the host TLS
 * buffer and, like the real one, flips the entry to polling mode when polling is enabled.
 *
 * Host shims: libnx reads the IPC buffer address from tpidrro_el0 (armGetTls); here it is a
 * static buffer. hidbus.c uses GCC's atomic_load_explicit on plain integers, which clang only
 * accepts as __atomic_load_n.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#undef atomic_load_explicit
#define atomic_load_explicit(p, o) __atomic_load_n((p), (o))
static _Alignas(16) unsigned char g_tls[0x200];
#define armGetTls armGetTls_aarch64
#include <switch/arm/tls.h>
#undef armGetTls
static inline void *armGetTls(void) { return g_tls; }
#include "../../nx/source/services/hidbus.c"

#define NREPLIES 8
static const uint8_t *g_replies;
static int g_reply_idx;
static u32 g_hosver;
static uint8_t g_shmem[0x1000];
static HidbusBusHandle g_cur;
static u32 g_mode;

u32 hosversionGet(void) { return g_hosver; }
u64 appletGetAppletResourceUserId(void) { return 0; }
void mutexLock(Mutex *m) { (void)m; }
void mutexUnlock(Mutex *m) { (void)m; }
Result smGetServiceWrapper(Service *out, SmServiceName name) {
    (void)name;
    memset(out, 0, sizeof *out);
    out->session = 0x100;
    out->own_handle = 1;
    return 0;
}
Result svcCloseHandle(Handle h) { (void)h; return 0; }
void shmemLoadRemote(SharedMemory *s, Handle h, size_t size, Permission perm) { memset(s, 0, sizeof *s); s->handle = h; s->size = size; s->perm = perm; }
Result shmemMap(SharedMemory *s) { s->map_addr = g_shmem; return 0; }
Result shmemClose(SharedMemory *s) { memset(s, 0, sizeof *s); return 0; }
Result tmemCreateFromMemory(TransferMemory *t, void *buf, size_t size, Permission perm) { (void)perm; memset(t, 0, sizeof *t); t->src_addr = buf; t->size = size; t->handle = 0x200; return 0; }
Result tmemClose(TransferMemory *t) { (void)t; return 0; }
void eventLoadRemote(Event *t, Handle h, bool ac) { memset(t, 0, sizeof *t); t->revent = h; t->autoclear = ac; }
void eventClose(Event *e) { memset(e, 0, sizeof *e); }
Result eventClear(Event *e) { (void)e; return 0; }
Result eventWait(Event *e, u64 timeout) { (void)e; (void)timeout; return 0; }
void hidLaCreateControllerFirmwareUpdateArg(HidLaControllerFirmwareUpdateArg *arg) { memset(arg, 0, sizeof *arg); }
Result hidLaShowControllerFirmwareUpdate(const HidLaControllerFirmwareUpdateArg *arg) { (void)arg; return MAKERESULT(Module_Libnx, LibnxError_LibAppletBadExit); }

/* The fake hidbus sysmodule: replies to the CMIF request in g_tls. */
Result svcSendSyncRequest(Handle session) {
    (void)session;
    HipcParsedRequest req = hipcParseRequest(g_tls);
    CmifInHeader *in = (CmifInHeader *)cmifGetAlignedDataStart(req.data.data_words, g_tls);
    u32 cmd = (req.meta.type == CmifCommandType_Request) ? in->command_id : 0xffffffff;

    uint8_t payload[16] = {0};
    if (g_reply_idx < NREPLIES) memcpy(payload, g_replies + 16 * g_reply_idx, 16);
    g_reply_idx++;
    u32 first;
    memcpy(&first, payload, 4);
    Result result = (first == 0xffffffff) ? MAKERESULT(218, 1) : 0;

    if (cmd == 11 && result == 0) {   /* EnableJoyPollingReceiveMode: the service switches the entry to polling */
        HidbusStatusManagerEntryCommon *c = _hidbusGetStatusManagerEntryCommon(g_cur.internal_index);
        c->is_polling_mode = 1;
        c->polling_mode = g_mode;
    }

    HipcRequest resp = hipcMakeRequestInline(g_tls, .type = 0, .num_data_words = (16 + 16 + 16) / 4, .num_copy_handles = 1);
    resp.copy_handles[0] = 0x300;
    CmifOutHeader *hdr = (CmifOutHeader *)cmifGetAlignedDataStart(resp.data_words, g_tls);
    hdr->magic = CMIF_OUT_HEADER_MAGIC;
    hdr->version = 0;
    hdr->result = result;
    hdr->token = 0;
    memcpy(hdr + 1, payload, sizeof payload);
    return 0;
}

/* Large enough for any polling mode's accessor (the caller picks the mode). */
#define MAX2(a, b) ((a) > (b) ? (a) : (b))
#define WORKBUF_SIZE MAX2(sizeof(HidbusJoyEnableSixAxisPollingDataAccessor), \
                          MAX2(sizeof(HidbusJoyDisableSixAxisPollingDataAccessor), sizeof(HidbusJoyButtonOnlyPollingDataAccessor)))

/*
 * The sysmodule is the ring's only writer and keeps it consistent: the entry at ring position
 * p carries sampling number base - ((latest_entry - p) mod 0xb), in both copies. libnx's reader
 * retries (forever, with a static buffer) until it sees that, so write the sampling numbers the
 * way the writer does; everything else in the ring (header, latest/total, out_size, data) stays
 * as the input gave it.
 */
#define SEQ(T) do { T *a = workbuf; s32 L = (s32)a->hdr.latest_entry; \
        for (s32 q = 0; q < 0xb; q++) { u64 sn = base - (u64)((((s64)L - q) % 0xb + 0xb) % 0xb); \
            a->entries[q].sampling_number = sn; a->entries[q].data.sampling_number = sn; } } while (0)
static void writer_sequence(void *workbuf, u32 mode, u64 base) {
    if (mode == HidbusJoyPollingMode_SixAxisSensorDisable) SEQ(HidbusJoyDisableSixAxisPollingDataAccessor);
    else if (mode == HidbusJoyPollingMode_SixAxisSensorEnable) SEQ(HidbusJoyEnableSixAxisPollingDataAccessor);
    else SEQ(HidbusJoyButtonOnlyPollingDataAccessor);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const size_t head = 3 + 16 * NREPLIES;
    if (size < head) return -1;
    static const u32 vers[4] = { MAKEHOSVERSION(5, 0, 0), MAKEHOSVERSION(6, 0, 0), MAKEHOSVERSION(8, 0, 0), MAKEHOSVERSION(10, 0, 0) };
    g_hosver = vers[data[0] & 3];
    g_mode = data[1] % 3;
    s32 count = 1 + data[2] % 11;   /* the API takes 1..; values above 0xa are clamped by libnx */
    g_replies = data + 3;
    g_reply_idx = 0;

    size_t rest = size - head;
    const uint8_t *p = data + head;
    void *workbuf = calloc(1, WORKBUF_SIZE);
    size_t n = rest < WORKBUF_SIZE ? rest : WORKBUF_SIZE;
    memcpy(workbuf, p, n);
    p += n; rest -= n;
    writer_sequence(workbuf, g_mode, 0x100 + data[2]);
    memset(g_shmem, 0, sizeof g_shmem);
    memcpy(g_shmem, p, rest < sizeof g_shmem ? rest : sizeof g_shmem);

    HidbusBusHandle h;
    memset(&h, 0, sizeof h);
    bool flag = false;
    if (R_SUCCEEDED(hidbusGetBusHandle(&h, &flag, HidNpadIdType_No1, HidbusBusType_RightJoyRail)) && flag) {
        g_cur = h;
        if (R_SUCCEEDED(hidbusInitialize(h))) {
            const u8 cmdbuf[4] = { 0x31, 0x01, 0, 0 };
            if (R_SUCCEEDED(hidbusEnableJoyPollingReceiveMode(h, cmdbuf, sizeof cmdbuf, workbuf, WORKBUF_SIZE, g_mode))) {
                HidbusJoyPollingReceivedData *recv = calloc(count, sizeof *recv);
                hidbusGetJoyPollingReceivedData(h, recv, count);
                free(recv);
                hidbusDisableJoyPollingReceiveMode(h);
            }
            hidbusFinalize(h);
        }
    }
    /* Reset what libnx keeps per device so the next input starts clean. */
    memset(g_hidbusDevices, 0, sizeof g_hidbusDevices);
    g_hidbusSharedmemRefCount = 0;
    memset(&g_hidbusSharedmem, 0, sizeof g_hidbusSharedmem);
    free(workbuf);
    return 0;
}
