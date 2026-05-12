extern "C" {
    #include <FreeRTOS.h>
    #include <task.h>

    #include <stdio.h>
    #include <stdint.h>
    #include <stddef.h>
    #include <string.h>

    void vInitializeBL602(void);

    #include <lwip/sockets.h>
    #include <lwip/inet.h>
    #include <lwip/tcpip.h>
    #include <lwip/netdb.h>

    #include <mbedtls/ccm.h>
    #include <mbedtls/hkdf.h>
    #include <mbedtls/md.h>
    #include <mbedtls/sha256.h>

    #include <bl_gpio.h>
    #include <looprt.h>
    #include <easyflash.h>
    #include "suas_ssd1306.h"

    extern int errno;
}

#include "pqkem_kem.h"
#include "coap_minimal.h"
#include "security_profile.h"
#include "splunk_hec.h"


extern "C" void task_wifi(void *param);
extern "C" volatile uint8_t g_wifi_ready;

#ifndef COAP_CODE_BAD_REQUEST
#define COAP_CODE_BAD_REQUEST 0x80
#endif
#ifndef COAP_CODE_UNAUTHORIZED
#define COAP_CODE_UNAUTHORIZED 0x81
#endif
#ifndef COAP_CODE_FORBIDDEN
#define COAP_CODE_FORBIDDEN 0x83
#endif
#ifndef COAP_CODE_NOT_FOUND
#define COAP_CODE_NOT_FOUND 0x84
#endif
#ifndef COAP_CODE_CONTENT
#define COAP_CODE_CONTENT 0x45
#endif
#ifndef COAP_CODE_TOO_MANY_REQUESTS
#define COAP_CODE_TOO_MANY_REQUESTS 0x9D
#endif
#ifndef COAP_CODE_SERVICE_UNAVAILABLE
#define COAP_CODE_SERVICE_UNAVAILABLE 0xA3
#endif

#ifndef COAP_CODE_RATE_LIMIT
#define COAP_CODE_RATE_LIMIT COAP_CODE_RATE_LIMIT_RESPONSE
#endif

#define WIFI_STACK_SIZE 512
static StackType_t wifi_stack[WIFI_STACK_SIZE];
static StaticTask_t wifi_task;

static constexpr uint8_t LED_PIN  = 5;
static constexpr uint8_t LED_ON   = 1;
static constexpr uint8_t LED_OFF  = 0;

static const size_t AEAD_KEY_LEN      = 16;
static const size_t AEAD_NONCE_LEN    = 12;
static const size_t AEAD_TAG_LEN      = 16;
static const size_t MAX_PLAINTEXT_LEN = 64;
static const uint16_t DEMO_PORT       = 5683;
static const size_t MAX_UDP           = 1200;

static constexpr uint32_t GW_KEM_STORE_MAGIC       = 0x474B5354u; 
static constexpr uint16_t GW_KEM_STORE_VERSION     = 7u;
static const char *GW_KEM_ENV_KEY                  = "pqc_gw_kem_store_v5";
enum MsgType : uint8_t {
    MSG_DATA = 3
};

struct AeadKey {
    uint8_t key[AEAD_KEY_LEN];
};

struct __attribute__((packed)) DataMsg {
    uint8_t type;
    uint8_t version;
    uint16_t kem_ct_len;
    uint16_t text_len;
    uint16_t reserved;
    uint32_t key_id;
    uint32_t sender_id;
    uint32_t sequence;
    uint8_t nonce[AEAD_NONCE_LEN];
    uint8_t buf[PQKEM_CIPHERTEXT_BYTES + MAX_PLAINTEXT_LEN + AEAD_TAG_LEN];
};

struct __attribute__((packed)) GwKemStore {
    uint32_t magic;
    uint16_t store_version;
    uint16_t variant;
    uint8_t strength;
    uint8_t reserved;
    GatewayKeyMetadataPayload meta;
    uint32_t allowed_sender_id;
    uint32_t last_sender_counter;
    uint8_t pk[PQKEM_PUBLIC_KEY_BYTES];
    uint8_t sk[PQKEM_SECRET_KEY_BYTES];
    uint32_t crc32;
};

struct PeerGuardState {
    uint32_t ip_addr;
    uint32_t window_start_ms;
    uint32_t meta_requests;
    uint32_t pk_requests;
    uint32_t data_requests;
    uint32_t auth_failures;
    uint32_t blocked_until_ms;
    uint8_t in_use;
};

static constexpr size_t NONCE_CACHE_SIZE = 128u;
static uint8_t g_nonce_cache[NONCE_CACHE_SIZE][AEAD_NONCE_LEN];
static uint8_t g_nonce_cache_valid[NONCE_CACHE_SIZE];
static size_t  g_nonce_cache_next = 0u;
static PeerGuardState g_peer_guards[PQC_PEER_TABLE_SIZE];

/* move large objects out of task stack */
static GwKemStore g_store;
static uint8_t g_udp_buf[MAX_UDP];
static DataMsg g_rx_msg;
static uint8_t g_ss[PQKEM_SHARED_SECRET_BYTES];
static uint8_t g_plaintext[MAX_PLAINTEXT_LEN + 1u];
static AeadKey g_aead_key;
static bool g_easyflash_ready = false;

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s = ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", buf[i]);
        if ((i + 1) % 16 == 0) {
            printf("\r\n");
        } else {
            printf(" ");
        }
    }
    if (len % 16 != 0) {
        printf("\r\n");
    }
}

static uint32_t generate_pairing_code(void)
{
    /*
     * Six-digit setup code for human-visible pairing.
     * This is NOT the Receiver fingerprint. The fingerprint remains
     * SHA-256(public_key). The random code only protects first-time
     * provisioning from accidental/blind acceptance.
     */
    uint8_t rnd[4] = {0, 0, 0, 0};
    pqkem_random_bytes(rnd, sizeof(rnd));
    const uint32_t v = ((uint32_t)rnd[0] << 24) |
                       ((uint32_t)rnd[1] << 16) |
                       ((uint32_t)rnd[2] << 8)  |
                       ((uint32_t)rnd[3]);
    return 100000u + (v % 900000u);
}

static void print_memory_stats(const char *label)
{
    printf("[MEM] %s: free_heap=%u min_ever_free=%u\r\n",
           label,
           (unsigned)xPortGetFreeHeapSize(),
           (unsigned)xPortGetMinimumEverFreeHeapSize());
}

static void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = reinterpret_cast<volatile uint8_t *>(ptr);
    while (len--) {
        *p++ = 0u;
    }
}

static void led_init()
{
    bl_gpio_enable_output(LED_PIN, 0, 0);
    bl_gpio_output_set(LED_PIN, LED_OFF);
}

static void led_blink(uint32_t on_ms, uint32_t off_ms, uint8_t times)
{
    for (uint8_t i = 0; i < times; ++i) {
        bl_gpio_output_set(LED_PIN, LED_ON);
        vTaskDelay(pdMS_TO_TICKS(on_ms));
        bl_gpio_output_set(LED_PIN, LED_OFF);
        vTaskDelay(pdMS_TO_TICKS(off_ms));
    }
}

static uint32_t monotonic_ms()
{
    return (uint32_t)xTaskGetTickCount() * (uint32_t)portTICK_PERIOD_MS;
}

static uint32_t crc32_ieee(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint32_t)data[i];
        for (uint8_t b = 0; b < 8u; ++b) {
            const uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1u) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static uint32_t gw_store_crc32(const GwKemStore *store)
{
    return crc32_ieee(reinterpret_cast<const uint8_t *>(store),
                      offsetof(GwKemStore, crc32));
}

static bool sha256_bytes(const uint8_t *data,
                         size_t len,
                         uint8_t out[PQC_PK_FINGERPRINT_LEN])
{
    mbedtls_sha256(data, len, out, 0);
    return true;
}

static bool hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) {
        return false;
    }

    int rc = mbedtls_hkdf(md,
                          salt,
                          salt_len,
                          ikm,
                          ikm_len,
                          info,
                          info_len,
                          okm,
                          okm_len);
    if (rc != 0) {
        printf("[Receiver] mbedtls_hkdf failed, rc=%d\r\n", rc);
    }
    return rc == 0;
}

static bool aead_decrypt(const AeadKey &key,
                         const uint8_t *nonce,
                         const uint8_t *aad,
                         size_t aad_len,
                         const uint8_t *ciphertext,
                         size_t ct_len,
                         const uint8_t *tag,
                         uint8_t *plaintext)
{
    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);

    int rc = mbedtls_ccm_setkey(&ctx,
                                MBEDTLS_CIPHER_ID_AES,
                                key.key,
                                (unsigned int)(AEAD_KEY_LEN * 8));
    if (rc != 0) {
        printf("[Receiver] mbedtls_ccm_setkey failed, rc=%d\r\n", rc);
        mbedtls_ccm_free(&ctx);
        return false;
    }

    rc = mbedtls_ccm_auth_decrypt(&ctx,
                                  ct_len,
                                  nonce,
                                  AEAD_NONCE_LEN,
                                  aad,
                                  aad_len,
                                  ciphertext,
                                  plaintext,
                                  tag,
                                  AEAD_TAG_LEN);
    mbedtls_ccm_free(&ctx);

    if (rc != 0) {
        printf("[Receiver] AEAD auth failed, rc=%d\r\n", rc);
        splunk_send_event("AEAD_AUTH_FAIL", "high", "packet_rejected");
    }
    return rc == 0;
}

static bool nonce_seen_before(const uint8_t *nonce)
{
    for (size_t i = 0; i < NONCE_CACHE_SIZE; ++i) {
        if (!g_nonce_cache_valid[i]) {
            continue;
        }
        if (memcmp(g_nonce_cache[i], nonce, AEAD_NONCE_LEN) == 0) {
            return true;
        }
    }
    return false;
}

static void remember_nonce(const uint8_t *nonce)
{
    memcpy(g_nonce_cache[g_nonce_cache_next], nonce, AEAD_NONCE_LEN);
    g_nonce_cache_valid[g_nonce_cache_next] = 1u;
    g_nonce_cache_next = (g_nonce_cache_next + 1u) % NONCE_CACHE_SIZE;
}

static PeerGuardState *peer_guard_get(uint32_t ip_addr)
{
    PeerGuardState *empty = NULL;
    for (size_t i = 0; i < PQC_PEER_TABLE_SIZE; ++i) {
        if (g_peer_guards[i].in_use && g_peer_guards[i].ip_addr == ip_addr) {
            return &g_peer_guards[i];
        }
        if (!g_peer_guards[i].in_use && empty == NULL) {
            empty = &g_peer_guards[i];
        }
    }
    if (empty) {
        memset(empty, 0, sizeof(*empty));
        empty->ip_addr = ip_addr;
        empty->in_use = 1u;
        empty->window_start_ms = monotonic_ms();
    }
    return empty;
}

static bool peer_guard_is_blocked(PeerGuardState *peer)
{
    if (!peer) {
        return false;
    }
    const uint32_t now = monotonic_ms();
    return (peer->blocked_until_ms != 0u) && ((int32_t)(peer->blocked_until_ms - now) > 0);
}

static void peer_guard_roll_window(PeerGuardState *peer, uint32_t window_ms)
{
    if (!peer) {
        return;
    }
    const uint32_t now = monotonic_ms();
    if ((now - peer->window_start_ms) > window_ms) {
        peer->window_start_ms = now;
        peer->meta_requests = 0u;
        peer->pk_requests = 0u;
        peer->data_requests = 0u;
    }
}

static bool peer_guard_allow_counter(PeerGuardState *peer,
                                     uint32_t window_ms,
                                     uint32_t max_requests,
                                     uint32_t *counter)
{
    if (!peer || !counter) {
        return false;
    }
    peer_guard_roll_window(peer, window_ms);
    (*counter)++;
    return *counter <= max_requests;
}

static void peer_guard_record_failure(PeerGuardState *peer, const char *reason)
{
    if (!peer) {
        return;
    }
    peer->auth_failures++;
    if (peer->auth_failures >= PQC_PEER_FAILS_TO_BLOCK) {
        peer->blocked_until_ms = monotonic_ms() + PQC_PEER_BLOCK_MS;
        peer->auth_failures = 0u;
        printf("[Receiver] Blocking peer after repeated failures: %s\r\n",
               reason ? reason : "unknown");
        splunk_send_event("SOURCE_BLOCKED", "medium", reason ? reason : "peer_blocked");
    }
}

static void peer_guard_record_success(PeerGuardState *peer)
{
    if (!peer) {
        return;
    }
    peer->auth_failures = 0u;
}

static bool easyflash_backend_init()
{
    if (g_easyflash_ready) {
        return true;
    }

    const EfErrCode rc = easyflash_init();
    if (rc != EF_NO_ERR) {
        printf("[Receiver] easyflash_init failed, rc=%d\r\n", (int)rc);
        return false;
    }

    g_easyflash_ready = true;
    printf("[Receiver] easyflash_init ok\r\n");
    return true;
}

static bool gw_store_load(GwKemStore *store)
{
    if (!easyflash_backend_init()) {
        return false;
    }

    size_t saved_len = 0u;
    memset(store, 0, sizeof(*store));
    const size_t read_len = ef_get_env_blob(GW_KEM_ENV_KEY,
                                            store,
                                            sizeof(*store),
                                            &saved_len);
    if (read_len != sizeof(*store) || saved_len != sizeof(*store)) {
        printf("[Receiver] gw_store_load: blob missing/short read_len=%u saved_len=%u\r\n",
               (unsigned)read_len,
               (unsigned)saved_len);
        return false;
    }

    if (store->magic != GW_KEM_STORE_MAGIC) {
        printf("[Receiver] gw_store_load: bad magic 0x%08lX\r\n",
               (unsigned long)store->magic);
        return false;
    }

    if (store->store_version != GW_KEM_STORE_VERSION) {
        printf("[Receiver] gw_store_load: bad version %u expected %u\r\n",
               (unsigned)store->store_version,
               (unsigned)GW_KEM_STORE_VERSION);
        return false;
    }

    if (store->variant != (uint16_t)PQKEM_VARIANT) {
        printf("[Receiver] gw_store_load: bad variant %u expected %u\r\n",
               (unsigned)store->variant,
               (unsigned)PQKEM_VARIANT);
        return false;
    }

    if (store->strength != (uint8_t)PQKEM_STRENGTH_LEVEL) {
        printf("[Receiver] gw_store_load: bad strength %u expected %u\r\n",
               (unsigned)store->strength,
               (unsigned)PQKEM_STRENGTH_LEVEL);
        return false;
    }

    if (store->meta.magic != PQC_META_MAGIC) {
        printf("[Receiver] gw_store_load: bad meta magic 0x%08lX\r\n",
               (unsigned long)store->meta.magic);
        return false;
    }

    const uint32_t actual_crc = gw_store_crc32(store);
    if (store->crc32 != actual_crc) {
        printf("[Receiver] gw_store_load: bad crc stored=0x%08lX actual=0x%08lX\r\n",
               (unsigned long)store->crc32,
               (unsigned long)actual_crc);
        return false;
    }

    printf("[Receiver] gw_store_load: existing keypair loaded from easyflash\r\n");
    return true;
}

static bool gw_store_save(const GwKemStore *store)
{
    if (!easyflash_backend_init()) {
        return false;
    }

    GwKemStore tmp;
    memcpy(&tmp, store, sizeof(tmp));
    tmp.crc32 = gw_store_crc32(&tmp);

    EfErrCode rc = ef_set_env_blob(GW_KEM_ENV_KEY, &tmp, sizeof(tmp));
    if (rc != EF_NO_ERR) {
        printf("[Receiver] gw_store_save: ef_set_env_blob failed rc=%d\r\n", (int)rc);
        return false;
    }

    rc = ef_save_env();
    if (rc != EF_NO_ERR) {
        printf("[Receiver] gw_store_save: ef_save_env failed rc=%d\r\n", (int)rc);
        return false;
    }

    GwKemStore verify;
    size_t saved_len = 0u;
    memset(&verify, 0, sizeof(verify));
    const size_t read_len = ef_get_env_blob(GW_KEM_ENV_KEY,
                                            &verify,
                                            sizeof(verify),
                                            &saved_len);
    if (read_len != sizeof(verify) || saved_len != sizeof(verify)) {
        printf("[Receiver] gw_store_save: verify short read_len=%u saved_len=%u\r\n",
               (unsigned)read_len,
               (unsigned)saved_len);
        return false;
    }

    const uint32_t verify_crc = gw_store_crc32(&verify);
    if (verify.crc32 != verify_crc) {
        printf("[Receiver] gw_store_save: verify crc mismatch stored=0x%08lX actual=0x%08lX\r\n",
               (unsigned long)verify.crc32,
               (unsigned long)verify_crc);
        return false;
    }

    printf("[Receiver] gw_store_save: keypair saved to easyflash\r\n");
    return true;
}

static bool gw_store_init_or_load(GwKemStore *store)
{
    if (gw_store_load(store)) {
        return true;
    }

    printf("[Receiver] gw_store_init_or_load: generating new keypair\r\n");

    memset(store, 0, sizeof(*store));
    store->magic = GW_KEM_STORE_MAGIC;
    store->store_version = GW_KEM_STORE_VERSION;
    store->variant = (uint16_t)PQKEM_VARIANT;
    store->strength = (uint8_t)PQKEM_STRENGTH_LEVEL;
    store->meta.magic = PQC_META_MAGIC;
    store->meta.key_id = 1u;
    store->meta.status = PQC_KEY_STATUS_ACTIVE;
    store->meta.rotation_required = 0u;
    store->meta.created_at_ms = monotonic_ms();
    store->meta.expires_at_ms = 0u;
    store->meta.message_count = 0u;
    store->meta.max_messages = PQC_KEY_MAX_MESSAGES_DEFAULT;
    store->allowed_sender_id = PQC_ALLOWED_SENDER_ID;
    store->last_sender_counter = 0u;
    store->crc32 = 0u;

    if (!pqkem_keygen(store->pk, store->sk)) {
        printf("[Receiver] gw_store_init_or_load: pqkem_keygen failed\r\n");
        return false;
    }

    if (!sha256_bytes(store->pk, PQKEM_PUBLIC_KEY_BYTES, store->meta.fingerprint)) {
        printf("[Receiver] gw_store_init_or_load: fingerprint hash failed\r\n");
        return false;
    }

    if (!gw_store_save(store)) {
        printf("[Receiver] gw_store_init_or_load: failed to persist new keypair\r\n");
        return false;
    }

    store->crc32 = gw_store_crc32(store);
    return true;
}

static void gw_meta_update_runtime(GwKemStore *store)
{
    store->meta.rotation_required = 0u;

    if (store->meta.status == PQC_KEY_STATUS_REVOKED) {
        store->meta.rotation_required = 1u;
        return;
    }

    if (store->meta.max_messages != 0u &&
        store->meta.message_count >= store->meta.max_messages) {
        store->meta.status = PQC_KEY_STATUS_ROTATION_REQUIRED;
        store->meta.rotation_required = 1u;
        return;
    }

    store->meta.status = PQC_KEY_STATUS_ACTIVE;
}

static void respond_simple(int sock_fd,
                           const struct sockaddr_in *src,
                           socklen_t srclen,
                           uint8_t code,
                           uint16_t msg_id,
                           const char *uri,
                           const uint8_t *payload,
                           size_t payload_len)
{
    uint8_t resp_buf[MAX_UDP];
    const size_t resp_len = coap_build_simple(resp_buf,
                                              sizeof(resp_buf),
                                              COAP_TYPE_ACK,
                                              code,
                                              msg_id,
                                              uri,
                                              payload,
                                              payload_len);
    if (resp_len > 0u) {
        sendto(sock_fd,
               resp_buf,
               resp_len,
               0,
               reinterpret_cast<const struct sockaddr *>(src),
               srclen);
    }
}

static void task_gateway(void *param)
{
    (void)param;

    printf("[Receiver] Task started (ML-KEM-%u, level %u)\r\n",
           (unsigned)PQKEM_VARIANT,
           (unsigned)PQKEM_STRENGTH_LEVEL);
    print_memory_stats("A_boot");

    constexpr uint16_t LOOPRT_STACKS_SIZE = 1024;
    static StackType_t proc_stack_looprt[LOOPRT_STACKS_SIZE];
    static StaticTask_t proc_task_looprt;
    looprt_start(proc_stack_looprt, LOOPRT_STACKS_SIZE, &proc_task_looprt);

    suas_ssd1306_init();
    suas_ssd1306_clear();
    suas_ssd1306_set_cursor(0, 0);
    suas_ssd1306_print_text((char *)"Waiting...");

    memset(&g_store, 0, sizeof(g_store));
    if (!gw_store_init_or_load(&g_store)) {
        printf("[Receiver] FATAL: unable to initialize gateway store\r\n");
        vTaskDelete(NULL);
        return;
    }

    gw_meta_update_runtime(&g_store);
    print_hex("[Receiver] PUBLIC KEY FINGERPRINT",
              g_store.meta.fingerprint,
              PQC_PK_FINGERPRINT_LEN);

    const uint32_t pairing_code = generate_pairing_code();
    printf("[Receiver] PAIRING_CODE=%06lu\r\n", (unsigned long)pairing_code);
    printf("[Receiver] Pairing code is generated by CTR-DRBG and is valid for this boot session\r\n");
    printf("[Receiver] Provision receiver fingerprint into sender before deployment\r\n");
    splunk_send_event("PAIRING_CODE_READY", "info", "pairing_code_generated");

    suas_ssd1306_clear();
    suas_ssd1306_set_cursor(0, 0);
    suas_ssd1306_print_text((char *)"PQC Receiver");
    suas_ssd1306_set_cursor(0, 2);
    char pairing_line[24];
    snprintf(pairing_line, sizeof(pairing_line), "Pair %06lu", (unsigned long)pairing_code);
    suas_ssd1306_print_text(pairing_line);
    /* Reset counter on boot so sender can always start from sequence=1 */
    g_store.last_sender_counter = 0u;
    (void)gw_store_save(&g_store);
    printf("[Receiver] Counter reset to 0 on boot (sender can start from 1)\r\n");
    printf("[Receiver] allowed_sender_id=0x%08lX last_counter=%lu\r\n",
           (unsigned long)g_store.allowed_sender_id,
           (unsigned long)g_store.last_sender_counter);
    print_memory_stats("B_key_loaded");
    printf("[MEM] gateway_task_stack_hwm=%u words\r\n",
           (unsigned)uxTaskGetStackHighWaterMark(NULL));
    splunk_send_event("KEY_ACTIVE", "info", "keypair_loaded");
    splunk_send_event("RECEIVER_FINGERPRINT_READY", "info", "fingerprint_available");

    int sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_fd < 0) {
        printf("[Receiver] socket() failed, errno=%d\r\n", errno);
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEMO_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock_fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        printf("[Receiver] bind() failed, errno=%d\r\n", errno);
        close(sock_fd);
        vTaskDelete(NULL);
        return;
    }

    printf("[Receiver] Listening on UDP port %u...\r\n", (unsigned)DEMO_PORT);
    splunk_send_event("MONITOR_ACTIVE", "info", "listening");
    splunk_send_event("GATEWAY_LISTENING", "info", "udp_5683_ready");

    while (1) {
        struct sockaddr_in src;
        socklen_t srclen = sizeof(src);
        const int n = recvfrom(sock_fd,
                               g_udp_buf,
                               sizeof(g_udp_buf),
                               0,
                               reinterpret_cast<struct sockaddr *>(&src),
                               &srclen);
        if (n <= 0) {
            continue;
        }

        PeerGuardState *peer = peer_guard_get(src.sin_addr.s_addr);

        CoapMessage cm;
        if (!coap_parse(&cm, g_udp_buf, (size_t)n)) {
            if (peer) {
                peer_guard_record_failure(peer, "coap_parse_fail");
            }
            continue;
        }

        if (peer_guard_is_blocked(peer)) {
            static const uint8_t msg[] = "SOURCE_BLOCKED";
            respond_simple(sock_fd,
                           &src,
                           srclen,
                           COAP_CODE_RATE_LIMIT,
                           cm.msg_id,
                           cm.uri_path[0] ? cm.uri_path : "blocked",
                           msg,
                           sizeof(msg) - 1u);
            continue;
        }

        if (cm.ver != 1u || cm.token_len != 0u || cm.type != COAP_TYPE_CON) {
            if (peer) {
                peer_guard_record_failure(peer, "bad_coap_header");
            }
            static const uint8_t msg[] = "BAD_COAP";
            respond_simple(sock_fd,
                           &src,
                           srclen,
                           COAP_CODE_BAD_REQUEST,
                           cm.msg_id,
                           cm.uri_path[0] ? cm.uri_path : "bad",
                           msg,
                           sizeof(msg) - 1u);
            continue;
        }

        gw_meta_update_runtime(&g_store);
        printf("[Receiver] CoAP code=0x%02X uri='%s' payload_len=%u\r\n",
               (unsigned)cm.code,
               cm.uri_path,
               (unsigned)cm.payload_len);

        if (cm.code == COAP_CODE_GET && strcmp(cm.uri_path, "pqkem-meta") == 0) {
            if (!peer_guard_allow_counter(peer,
                                          PQC_RATE_LIMIT_WINDOW_MS,
                                          PQC_META_RATE_LIMIT_MAX_REQUESTS,
                                          peer ? &peer->meta_requests : NULL)) {
                static const uint8_t msg[] = "RATE_LIMIT";
                splunk_send_event("RATE_LIMIT_HIT", "medium", "meta_throttle");
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_RATE_LIMIT,
                               cm.msg_id,
                               "pqkem-meta",
                               msg,
                               sizeof(msg) - 1u);
                continue;
            }
            splunk_send_event("META_REQUEST", "info", "meta_served");
            respond_simple(sock_fd,
                           &src,
                           srclen,
                           COAP_CODE_CONTENT,
                           cm.msg_id,
                           "pqkem-meta",
                           reinterpret_cast<const uint8_t *>(&g_store.meta),
                           sizeof(g_store.meta));
            continue;
        }

        if (cm.code == COAP_CODE_GET && strcmp(cm.uri_path, "pqkem-pk") == 0) {
            if (!peer_guard_allow_counter(peer,
                                          PQC_RATE_LIMIT_WINDOW_MS,
                                          PQC_RATE_LIMIT_MAX_REQUESTS,
                                          peer ? &peer->pk_requests : NULL)) {
                static const uint8_t msg[] = "RATE_LIMIT";
                splunk_send_event("RATE_LIMIT_HIT", "medium", "temporary_throttle");
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_RATE_LIMIT,
                               cm.msg_id,
                               "pqkem-pk",
                               msg,
                               sizeof(msg) - 1u);
                continue;
            }

            if (g_store.meta.status == PQC_KEY_STATUS_REVOKED) {
                static const uint8_t msg[] = "REVOKED";
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_UNAUTHORIZED,
                               cm.msg_id,
                               "pqkem-pk",
                               msg,
                               sizeof(msg) - 1u);
                continue;
            }

            splunk_send_event("PK_REQUEST", "info", "pk_served");
            respond_simple(sock_fd,
                           &src,
                           srclen,
                           COAP_CODE_CONTENT,
                           cm.msg_id,
                           "pqkem-pk",
                           g_store.pk,
                           PQKEM_PUBLIC_KEY_BYTES);
            continue;
        }

        if (cm.code == COAP_CODE_POST && strcmp(cm.uri_path, "pqkem-data") == 0) {
            if (!peer_guard_allow_counter(peer,
                                          PQC_DATA_RATE_LIMIT_WINDOW_MS,
                                          PQC_DATA_RATE_LIMIT_MAX_REQUESTS,
                                          peer ? &peer->data_requests : NULL)) {
                static const uint8_t msg[] = "RATE_LIMIT";
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_RATE_LIMIT,
                               cm.msg_id,
                               "pqkem-data",
                               msg,
                               sizeof(msg) - 1u);
                continue;
            }

            splunk_send_event("DATA_REQUEST", "info", "encrypted_data_received");
            gw_meta_update_runtime(&g_store);
            if (g_store.meta.rotation_required ||
                g_store.meta.status == PQC_KEY_STATUS_ROTATION_REQUIRED ||
                g_store.meta.status == PQC_KEY_STATUS_REVOKED) {
                static const uint8_t msg[] = "KEY_ROTATION_REQUIRED";
                splunk_send_event("KEY_ROTATION_REQUIRED", "medium", "data_rejected_until_reprovisioned");
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_UNAUTHORIZED,
                               cm.msg_id,
                               "pqkem-data",
                               msg,
                               sizeof(msg) - 1u);
                continue;
            }

            const size_t header_len = offsetof(DataMsg, buf);
            if (cm.payload_len < header_len + PQKEM_CIPHERTEXT_BYTES + AEAD_TAG_LEN) {
                static const uint8_t msg[] = "BAD_LEN";
                if (peer) { peer_guard_record_failure(peer, "bad_len"); }
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_BAD_REQUEST,
                               cm.msg_id,
                               "pqkem-data",
                               msg,
                               sizeof(msg) - 1u);
                continue;
            }

            memset(&g_rx_msg, 0, sizeof(g_rx_msg));
            const size_t copy_len = (cm.payload_len > sizeof(g_rx_msg)) ? sizeof(g_rx_msg) : cm.payload_len;
            memcpy(&g_rx_msg, cm.payload, copy_len);

            if (g_rx_msg.type != MSG_DATA || g_rx_msg.version != PQC_PROTOCOL_VERSION) {
                static const uint8_t r[] = "BAD_PROTO";
                if (peer) { peer_guard_record_failure(peer, "bad_proto"); }
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_BAD_REQUEST,
                               cm.msg_id,
                               "pqkem-data",
                               r,
                               sizeof(r) - 1u);
                continue;
            }
            if (g_rx_msg.kem_ct_len != PQKEM_CIPHERTEXT_BYTES) {
                static const uint8_t r[] = "BAD_CT";
                if (peer) { peer_guard_record_failure(peer, "bad_ct"); }
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_BAD_REQUEST,
                               cm.msg_id,
                               "pqkem-data",
                               r,
                               sizeof(r) - 1u);
                continue;
            }
            if (g_rx_msg.text_len == 0u || g_rx_msg.text_len > MAX_PLAINTEXT_LEN) {
                static const uint8_t r[] = "BAD_TEXTLEN";
                if (peer) { peer_guard_record_failure(peer, "bad_textlen"); }
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_BAD_REQUEST,
                               cm.msg_id,
                               "pqkem-data",
                               r,
                               sizeof(r) - 1u);
                continue;
            }
            if (g_rx_msg.key_id != g_store.meta.key_id) {
                static const uint8_t r[] = "BAD_KEYID";
                if (peer) { peer_guard_record_failure(peer, "bad_keyid"); }
                splunk_send_event("KEY_ID_FAIL", "high", "wrong_key_id");
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_UNAUTHORIZED,
                               cm.msg_id,
                               "pqkem-data",
                               r,
                               sizeof(r) - 1u);
                continue;
            }
            if (g_rx_msg.sender_id != g_store.allowed_sender_id) {
                static const uint8_t r[] = "BAD_SENDER";
                if (peer) { peer_guard_record_failure(peer, "bad_sender"); }
                splunk_send_event("SENDER_AUTH_FAIL", "high", "wrong_sender_id");
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_UNAUTHORIZED,
                               cm.msg_id,
                               "pqkem-data",
                               r,
                               sizeof(r) - 1u);
                continue;
            }
            if (g_rx_msg.sequence == 0u || g_rx_msg.sequence <= g_store.last_sender_counter) {
                static const uint8_t r[] = "REPLAY_SEQ";
                if (peer) { peer_guard_record_failure(peer, "replay_seq"); }
                splunk_send_event("REPLAY_REJECT", "medium", "sequence_replay");
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_UNAUTHORIZED,
                               cm.msg_id,
                               "pqkem-data",
                               r,
                               sizeof(r) - 1u);
                continue;
            }
            if (nonce_seen_before(g_rx_msg.nonce)) {
                static const uint8_t r[] = "REPLAY_NONCE";
                if (peer) { peer_guard_record_failure(peer, "replay_nonce"); }
                splunk_send_event("REPLAY_REJECT", "medium", "nonce_replay");
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_UNAUTHORIZED,
                               cm.msg_id,
                               "pqkem-data",
                               r,
                               sizeof(r) - 1u);
                continue;
            }

            const size_t expected_len =
                header_len + g_rx_msg.kem_ct_len + g_rx_msg.text_len + AEAD_TAG_LEN;
            if (cm.payload_len != expected_len) {
                static const uint8_t r[] = "BAD_WIRELEN";
                if (peer) { peer_guard_record_failure(peer, "bad_wirelen"); }
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_BAD_REQUEST,
                               cm.msg_id,
                               "pqkem-data",
                               r,
                               sizeof(r) - 1u);
                continue;
            }

            uint8_t *kem_ct = g_rx_msg.buf;
            uint8_t *ciphertext = g_rx_msg.buf + g_rx_msg.kem_ct_len;
            uint8_t *tag = ciphertext + g_rx_msg.text_len;

            memset(g_ss, 0, sizeof(g_ss));
            memset(g_plaintext, 0, sizeof(g_plaintext));
            memset(&g_aead_key, 0, sizeof(g_aead_key));

            const uint32_t t0 = monotonic_ms();
            if (!pqkem_decapsulate(kem_ct, g_store.sk, g_ss)) {
                static const uint8_t r[] = "KEM_FAIL";
                if (peer) { peer_guard_record_failure(peer, "kem_fail"); }
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_BAD_REQUEST,
                               cm.msg_id,
                               "pqkem-data",
                               r,
                               sizeof(r) - 1u);
                secure_zero(g_ss, sizeof(g_ss));
                continue;
            }
            const uint32_t kem_ms = monotonic_ms() - t0;
            splunk_send_event("KEM_DECAP_OK", "info", "shared_secret_decapsulated");

            const uint8_t info[] = "ML-KEM-AEAD";
            if (!hkdf_sha256(g_ss,
                             PQKEM_SHARED_SECRET_BYTES,
                             NULL,
                             0,
                             info,
                             sizeof(info) - 1u,
                             g_aead_key.key,
                             sizeof(g_aead_key.key))) {
                static const uint8_t r[] = "HKDF_FAIL";
                if (peer) { peer_guard_record_failure(peer, "hkdf_fail"); }
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_BAD_REQUEST,
                               cm.msg_id,
                               "pqkem-data",
                               r,
                               sizeof(r) - 1u);
                secure_zero(g_ss, sizeof(g_ss));
                continue;
            }
            splunk_send_event("HKDF_DONE", "info", "aead_key_derived");
            secure_zero(g_ss, sizeof(g_ss));

            const uint32_t t1 = monotonic_ms();
            const bool ok = aead_decrypt(g_aead_key,
                                         g_rx_msg.nonce,
                                         reinterpret_cast<const uint8_t *>(&g_rx_msg),
                                         header_len,
                                         ciphertext,
                                         g_rx_msg.text_len,
                                         tag,
                                         g_plaintext);
            const uint32_t aead_ms = monotonic_ms() - t1;
            secure_zero(&g_aead_key, sizeof(g_aead_key));

            if (!ok) {
                static const uint8_t r[] = "AUTH_FAIL";
                if (peer) { peer_guard_record_failure(peer, "auth_fail"); }
                suas_ssd1306_clear();
                suas_ssd1306_set_cursor(0, 0);
                suas_ssd1306_print_text((char *)"AUTH FAIL");
                led_blink(80, 80, 3);
                respond_simple(sock_fd,
                               &src,
                               srclen,
                               COAP_CODE_BAD_REQUEST,
                               cm.msg_id,
                               "pqkem-data",
                               r,
                               sizeof(r) - 1u);
                secure_zero(g_plaintext, sizeof(g_plaintext));
                continue;
            }

            splunk_send_event("AEAD_DECRYPT_OK", "info", "message_authenticated");
            g_store.last_sender_counter = g_rx_msg.sequence;
            g_store.meta.message_count++;
            gw_meta_update_runtime(&g_store);
            remember_nonce(g_rx_msg.nonce);
            (void)gw_store_save(&g_store);

            g_plaintext[g_rx_msg.text_len] = 0u;
            printf("[Receiver] KEM=%lu ms, AEAD=%lu ms\r\n",
                   (unsigned long)kem_ms,
                   (unsigned long)aead_ms);
            printf("[Receiver] Decrypted msg: '%s'\r\n", reinterpret_cast<char *>(g_plaintext));
            printf("[Receiver] key_id=%lu counter=%lu message_count=%lu/%lu\r\n",
                   (unsigned long)g_store.meta.key_id,
                   (unsigned long)g_store.last_sender_counter,
                   (unsigned long)g_store.meta.message_count,
                   (unsigned long)g_store.meta.max_messages);
            print_memory_stats("C_session_done");
            printf("[MEM] gateway_task_stack_hwm=%u words\r\n",
                   (unsigned)uxTaskGetStackHighWaterMark(NULL));

            peer_guard_record_success(peer);
            splunk_send_event("MSG_DECRYPTED", "info", "message_decrypted");
            suas_ssd1306_clear();
            suas_ssd1306_set_cursor(0, 0);
            suas_ssd1306_print_text(reinterpret_cast<char *>(g_plaintext));
            led_blink(600, 100, 1);

            static const uint8_t r[] = "OK";
            respond_simple(sock_fd,
                           &src,
                           srclen,
                           COAP_CODE_CHANGED,
                           cm.msg_id,
                           "pqkem-data",
                           r,
                           sizeof(r) - 1u);
            secure_zero(g_plaintext, sizeof(g_plaintext));
            continue;
        }

        static const uint8_t r[] = "NOT_FOUND";
        respond_simple(sock_fd,
                       &src,
                       srclen,
                       COAP_CODE_NOT_FOUND,
                       cm.msg_id,
                       cm.uri_path,
                       r,
                       sizeof(r) - 1u);
    }
}

static void wait_for_wifi_ready()
{
    while (!g_wifi_ready) {
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

static void task_pq_starter(void *param)
{
    (void)param;
    printf("[starter] Waiting for Wi-Fi...\r\n");
    wait_for_wifi_ready();
    printf("[starter] Wi-Fi ready, starting gateway task\r\n");
    printf("[Splunk-R] Direct mode: token is build-time; Splunk host IP is auto-discovered by UDP/9998 unless SPLUNK_STATIC_HOST is set\r\n");

    print_memory_stats("wifi_ready");
    splunk_send_event("WIFI_CONNECTED", "info", "wifi_up");
    splunk_send_event("SPLUNK_DIRECT_READY", "info", "direct_hec_ready");

    BaseType_t rc = xTaskCreate(task_gateway, "gw", 12288, NULL, 10, NULL);
    printf("[starter] xTaskCreate rc=%ld\r\n", (long)rc);
    vTaskDelete(NULL);
}

extern "C" void app_main(void)
{
    vInitializeBL602();
    led_init();

    printf("\r\n=== Receiver: Hardened ML-KEM-%u gateway === %s %s ===\r\n",
           (unsigned)PQKEM_VARIANT,
           __DATE__,
           __TIME__);
    print_memory_stats("app_start");

    xTaskCreateStatic(task_wifi,
                      "wifi",
                      WIFI_STACK_SIZE,
                      NULL,
                      16,
                      wifi_stack,
                      &wifi_task);
    tcpip_init(NULL, NULL);

    BaseType_t rc = xTaskCreate(task_pq_starter, "pqstart", 2048, NULL, 9, NULL);
    printf("[main] starter xTaskCreate rc=%ld\r\n", (long)rc);

    vTaskStartScheduler();
    printf("[main] vTaskStartScheduler returned unexpectedly\r\n");
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

extern "C" int bfl_main(void)
{
    app_main();
    return 0;
}
