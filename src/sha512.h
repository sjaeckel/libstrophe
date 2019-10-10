/* public api for Thomas Pornin's BearSSL SHA-512 implementation */

/** @file
 *  SHA-512 hash API.
 */

#ifndef LIBSTROPHE_SHA512_H__
#define LIBSTROPHE_SHA512_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "sha.h"

typedef struct {
    uint64_t  length, state[8];
    uint8_t curlen;
    uint8_t buf[128];
} sha512_context;

#define SHA512_DIGEST_SIZE 64

void sha512_init(sha512_context *cc);
void sha512_process(sha512_context *cc, const uint8_t *data, size_t len);
void sha512_done(sha512_context *cc, uint8_t *dst);

void sha512_hash(const uint8_t *data, size_t len, uint8_t *digest);
#ifdef __cplusplus
}
#endif

#endif /* LIBSTROPHE_SHA512_H__ */
