/* Force-included (-include) when compiling nx/source/runtime/util/inet_addr.c on a glibc host.
 * libnx's own inet_* are renamed nx_inet_* (command line -D) so the harness calls libnx's code,
 * not glibc's. glibc names the BSD __u6_addr32 member __in6_u.__u6_addr32; map it after the
 * header is parsed so only libnx's source sees the alias. */
#pragma once
#include <netinet/in.h>
#include <arpa/inet.h>
#define __u6_addr32 __in6_u.__u6_addr32
