#ifndef __XEN_SHA256_H
#define __XEN_SHA256_H

#include <xen/inttypes.h>

#define SHA256_DIGEST_SIZE  32

void sha256_hash(const u8 *data, unsigned int len, u8 *out);

#endif /* !__XEN_SHA256_H */
