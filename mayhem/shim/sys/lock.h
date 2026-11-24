/* Host shim for newlib's <sys/lock.h> (devkitA64 flavour, used by libnx kernel/mutex.h). */
#pragma once
#include <stdint.h>
typedef uint32_t _LOCK_T;
typedef struct { uint32_t lock; uint32_t thread_tag; uint32_t counter; } _LOCK_RECURSIVE_T;
typedef struct { uint32_t cond; } _COND_T;
