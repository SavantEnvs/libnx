/*
 * fuzz_parcel — libnx binder Parcel reply handling through its public API
 * (switch/display/parcel.h, nx/source/display/parcel.c): parcelTransact() validates the
 * ParcelHeader of the binder reply and copies the payload, then the parcelRead* helpers
 * consume it the way the IGraphicBufferProducer client (buffer_producer.c) does.
 *
 * Input: byte 0 = length L of the read script, bytes 1..L = script (one read op per byte),
 * the rest = the raw binder reply (ParcelHeader + payload) the vi service would return,
 * served by the binderTransactParcel() stand-in. binder.c (the IPC) needs Horizon's TLS
 * and buffer_producer.c uses a GCC-only VLA-in-struct, so neither builds with clang on a
 * host; binderTransactParcel / binderConvertErrorCode are stand-ins here.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <switch/types.h>
#include <switch/result.h>
#include <switch/display/parcel.h>

static const uint8_t *g_reply;
static size_t g_reply_size;

Result binderTransactParcel(Binder *b, u32 code, void *in, size_t in_size, void *out, size_t out_size, u32 flags) {
    (void)b; (void)code; (void)in; (void)in_size; (void)flags;
    size_t n = g_reply_size < out_size ? g_reply_size : out_size;
    memcpy(out, g_reply, n);
    return 0;
}

Result binderConvertErrorCode(s32 code) {
    return code >= 0 ? 0 : MAKERESULT(Module_LibnxBinder, LibnxBinderError_Unknown);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    size_t L = data[0];
    if (L > size - 1) L = size - 1;
    const uint8_t *script = data + 1;
    g_reply = data + 1 + L;
    g_reply_size = size - 1 - L;

    Binder b;
    memset(&b, 0, sizeof b);
    b.created = b.initialized = true;
    Parcel req, reply;
    parcelCreate(&req);
    parcelCreate(&reply);
    parcelWriteInterfaceToken(&req, "android.gui.IGraphicBufferProducer");
    parcelWriteInt32(&req, (s32)L);
    if (R_FAILED(parcelTransact(&b, 1, &req, &reply))) return 0;

    uint8_t tmp[PARCEL_MAX_PAYLOAD];
    for (size_t i = 0; i < L; i++) {
        uint8_t op = script[i];
        switch (op & 3) {
        case 0: binderConvertErrorCode(parcelReadInt32(&reply)); break;
        case 1: parcelReadUInt32(&reply); break;
        case 2: {
            size_t sz = 0;
            void *p = parcelReadFlattenedObject(&reply, &sz);
            if (p && sz <= sizeof tmp) memcpy(tmp, p, sz);
            break;
        }
        default: parcelReadData(&reply, tmp, (size_t)(op >> 2) * 4); break;
        }
    }
    return 0;
}
