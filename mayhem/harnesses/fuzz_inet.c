/*
 * fuzz_inet — libnx address parsers/formatters (nx/source/runtime/util/inet_addr.c).
 * libnx's inet_* are compiled renamed to nx_inet_* (see build.sh) so this calls libnx's code,
 * not glibc's. The input is a NUL-terminated string fed to inet_pton (AF_INET and AF_INET6),
 * inet_aton and inet_addr; its first 16 bytes are also formatted with inet_ntop into
 * destination buffers of every size up to the maximum, and inet_ntoa.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>

int nx_inet_pton(int af, const char *src, void *dst);
const char *nx_inet_ntop(int af, const void *src, char *dst, socklen_t size);
int nx_inet_aton(const char *cp, struct in_addr *inp);
in_addr_t nx_inet_addr(const char *cp);
char *nx_inet_ntoa(struct in_addr in);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *s = malloc(size + 1);
    memcpy(s, data, size);
    s[size] = 0;
    /* inet_pton's contract: dst is a struct in_addr / struct in6_addr. */
    struct in_addr a4, ia;
    struct in6_addr a6;
    nx_inet_pton(AF_INET, s, &a4);
    nx_inet_pton(AF_INET6, s, &a6);
    nx_inet_pton(AF_UNIX, s, &a6);
    nx_inet_aton(s, &ia);
    nx_inet_addr(s);
    free(s);

    struct in6_addr raw;
    memset(&raw, 0, sizeof raw);
    memcpy(&raw, data, size < 16 ? size : 16);
    for (socklen_t n = 0; n <= 46; n++) {
        char *dst = malloc(n ? n : 1);
        nx_inet_ntop(AF_INET, &raw, dst, n);
        nx_inet_ntop(AF_INET6, &raw, dst, n);
        free(dst);
    }
    memcpy(&ia, &raw, 4);
    nx_inet_ntoa(ia);
    return 0;
}
