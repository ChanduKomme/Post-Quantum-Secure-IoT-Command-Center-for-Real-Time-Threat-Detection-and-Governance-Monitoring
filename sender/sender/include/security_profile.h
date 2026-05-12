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

#ifndef PQC_SENDER_ID
#define PQC_SENDER_ID 0x53454E31u
#endif

/* Fixed receiver IP (empty string = use last known or discovery) */
#ifndef PQC_GATEWAY_STATIC_IP
#define PQC_GATEWAY_STATIC_IP ""
#endif

/* 1 = allow broadcast discovery fallback, 0 = static IP only */
#ifndef PQC_ALLOW_BROADCAST_DISCOVERY
#define PQC_ALLOW_BROADCAST_DISCOVERY 1u
#endif

#define PQC_KEY_STATUS_ACTIVE            1u
#define PQC_KEY_STATUS_REVOKED           2u
#define PQC_KEY_STATUS_ROTATION_REQUIRED 3u
#define PQC_KEY_STATUS_RETIRED           4u

#ifndef PQC_KEY_MAX_MESSAGES_DEFAULT
#define PQC_KEY_MAX_MESSAGES_DEFAULT 1000u
#endif

#ifndef PQC_RATE_LIMIT_WINDOW_MS
#define PQC_RATE_LIMIT_WINDOW_MS 1000u
#endif

#ifndef PQC_RATE_LIMIT_MAX_REQUESTS
#define PQC_RATE_LIMIT_MAX_REQUESTS 8u
#endif

#ifndef PQC_META_RATE_LIMIT_MAX_REQUESTS
#define PQC_META_RATE_LIMIT_MAX_REQUESTS 16u
#endif

#ifndef PQC_DATA_RATE_LIMIT_WINDOW_MS
#define PQC_DATA_RATE_LIMIT_WINDOW_MS 1000u
#endif

#ifndef PQC_DATA_RATE_LIMIT_MAX_REQUESTS
#define PQC_DATA_RATE_LIMIT_MAX_REQUESTS 8u
#endif

#ifndef PQC_ALLOWED_SENDER_ID
#define PQC_ALLOWED_SENDER_ID PQC_SENDER_ID
#endif

#ifndef PQC_PEER_TABLE_SIZE
#define PQC_PEER_TABLE_SIZE 8u
#endif

#ifndef PQC_PEER_FAILS_TO_BLOCK
#define PQC_PEER_FAILS_TO_BLOCK 5u
#endif

#ifndef PQC_PEER_BLOCK_MS
#define PQC_PEER_BLOCK_MS 30000u
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
    0x3E, 0x94, 0x61, 0xA5, 0x73, 0xD0, 0xF6, 0x95,
    0x1A, 0x78, 0x68, 0x83, 0xEB, 0x34, 0x86, 0xCA,
    0x3A, 0xE9, 0xCF, 0x48, 0xDB, 0xCD, 0x88, 0xC8,
    0xFA, 0x53, 0xBE, 0xBE, 0xFD, 0x78, 0xF3, 0x5C
};

static inline bool pqc_fingerprint_is_provisioned(void) {
    for (size_t i = 0; i < PQC_PK_FINGERPRINT_LEN; ++i) {
        if (kProvisionedGatewayPkFingerprint[i] != 0u) {
            return true;
        }
    }
    return false;
}

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_PROFILE_H */
