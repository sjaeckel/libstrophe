/* public api for Thomas Pornin's BearSSL SHA-256 implementation */

/** @file
 *  SHA-256 hash API.
 */

#ifndef LIBSTROPHE_SHA256_H__
#define LIBSTROPHE_SHA256_H__

#ifdef __cplusplus
extern "C" {
#endif

/* make sure the stdint.h types are available */
#include "ostypes.h"


typedef struct {
    uint64_t length;
    uint32_t state[8], curlen;
    uint8_t buf[64];
} sha256_context;

#define SHA256_DIGEST_SIZE 32

void sha256_init(sha256_context * md);
void sha256_process(sha256_context * md, const uint8_t *in, size_t inlen);
void sha256_done(sha256_context * md, uint8_t *out);

void sha256_hash(const uint8_t *data, size_t len, uint8_t *digest);
#ifdef __cplusplus
}
#endif

#endif /* LIBSTROPHE_SHA256_H__ */
