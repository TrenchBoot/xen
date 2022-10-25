#ifndef __XEN_SHA1_H
#define __XEN_SHA1_H

#include <xen/inttypes.h>

#define SHA1_DIGEST_SIZE  20

void sha1_hash(const u8 *data, unsigned int len, u8 *out);

#endif /* !__XEN_SHA1_H */
