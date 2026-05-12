#ifndef SECURITY_PROFILE_H
#define SECURITY_PROFILE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQC_META_MAGIC 0x504D4554u /* PMET */
#define PQC_PK_FINGERPRINT_LEN 32u

#define PQC_PK_AUTH_MODE_TOFU   0u
#define PQC_PK_AUTH_MODE_STRICT 1u

#ifndef PQC_PK_AUTH_MODE
#define PQC_PK_AUTH_MODE PQC_PK_AUTH_MODE_STRICT
#endif

#ifndef PQC_PROTOCOL_VERSION
#define PQC_PROTOCOL_VERSION 1u
#endif

#ifndef PQC_ALLOWED_SENDER_ID
#define PQC_ALLOWED_SENDER_ID 0x53454E31u /* 'SEN1' */
#endif

#ifndef PQC_USE_FACTORY_IDENTITY
#define PQC_USE_FACTORY_IDENTITY 0u
#endif

#define PQC_KEY_STATUS_ACTIVE            1u
#define PQC_KEY_STATUS_REVOKED           2u
#define PQC_KEY_STATUS_ROTATION_REQUIRED 3u
#define PQC_KEY_STATUS_RETIRED           4u

#ifndef PQC_KEY_MAX_MESSAGES_DEFAULT
#define PQC_KEY_MAX_MESSAGES_DEFAULT 99999u
#endif

#ifndef PQC_RATE_LIMIT_WINDOW_MS
#define PQC_RATE_LIMIT_WINDOW_MS 1000u
#endif

#ifndef PQC_RATE_LIMIT_MAX_REQUESTS
#define PQC_RATE_LIMIT_MAX_REQUESTS 8u
#endif

#ifndef PQC_DATA_RATE_LIMIT_WINDOW_MS
#define PQC_DATA_RATE_LIMIT_WINDOW_MS 1000u
#endif

#ifndef PQC_DATA_RATE_LIMIT_MAX_REQUESTS
#define PQC_DATA_RATE_LIMIT_MAX_REQUESTS 8u
#endif

/* Default to RFC 7252 4.03; opt in to RFC 8516 4.29 with -DPQC_RATE_LIMIT_USE_429 */
#ifdef PQC_RATE_LIMIT_USE_429
    #ifndef COAP_CODE_RATE_LIMIT_RESPONSE
    #define COAP_CODE_RATE_LIMIT_RESPONSE 0x9Du
    #endif
#else
    #ifndef COAP_CODE_RATE_LIMIT_RESPONSE
    #define COAP_CODE_RATE_LIMIT_RESPONSE 0x83u
    #endif
#endif

#ifndef PQC_PEER_TABLE_SIZE
#define PQC_PEER_TABLE_SIZE 16u
#endif

#ifndef PQC_PEER_BLOCK_MS
#define PQC_PEER_BLOCK_MS 30000u
#endif

#ifndef PQC_PEER_FAILS_TO_BLOCK
#define PQC_PEER_FAILS_TO_BLOCK 4u
#endif

#ifndef PQC_META_RATE_LIMIT_MAX_REQUESTS
#define PQC_META_RATE_LIMIT_MAX_REQUESTS 16u
#endif

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t key_id;
    uint32_t created_at_ms;
    uint32_t expires_at_ms;
    uint32_t message_count;
    uint32_t max_messages;
    uint8_t status;
    uint8_t rotation_required;
    uint8_t reserved0;
    uint8_t reserved1;
    uint8_t fingerprint[PQC_PK_FINGERPRINT_LEN];
} GatewayKeyMetadataPayload;

static const uint8_t kProvisionedGatewayPkFingerprint[PQC_PK_FINGERPRINT_LEN] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static inline bool pqc_fingerprint_is_provisioned(void) {
    for (size_t i = 0; i < PQC_PK_FINGERPRINT_LEN; ++i) {
        if (kProvisionedGatewayPkFingerprint[i] != 0u) return true;
    }
    return false;
}

#ifdef __cplusplus
}
#endif

#endif
