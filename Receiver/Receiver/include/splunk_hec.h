#ifndef SPLUNK_HEC_H
#define SPLUNK_HEC_H

/*
 * splunk_hec.h — Auto-discovering Wi-Fi → Splunk HEC event sender
 * ─────────────────────────────────────────────────────────────────
 * The BL602 board discovers the Splunk server automatically via UDP
 * broadcast. No hardcoded IP address is needed.
 *
 * HOW IT WORKS:
 *   1. On first use, the board broadcasts "PQC_SPLUNK_DISCOVER" on
 *      the local network (UDP port 9998).
 *   2. The PC running Splunk must also run:
 *        python3 integrations/splunk_hackerone_jira/splunk/splunk_discovery_server.py
 *   3. The discovery server responds with the PC's IP and HEC port.
 *   4. The board caches the IP and sends all HEC events directly over
 *      Wi-Fi — no USB cable, no Python bridge required.
 *
 * CONFIGURATION (only if you want to override auto-discovery):
 *   #define SPLUNK_STATIC_HOST "192.168.1.100"  // bypass discovery
 *
 * SPLUNK_TOKEN: set at build time via -DSPLUNK_HEC_TOKEN=<token>
 * or leave the default which reads from your .env during HEC check.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <lwip/inet.h>
#include <lwip/netif.h>

/* ── Token: inject at build time; never commit real HEC tokens. ───── */
#ifndef SPLUNK_HEC_TOKEN
#define SPLUNK_HEC_TOKEN  ""
#endif

/* ── Fixed settings ──────────────────────────────────────────────── */
#ifndef SPLUNK_HEC_PORT
#define SPLUNK_HEC_PORT         "8088"
#endif
#define SPLUNK_INDEX            "pqc_iot"
#define SPLUNK_SOURCE           "pqc_iot_bl602"
#define SPLUNK_SRCTYPE          "pqc:iot:event"
#define SPLUNK_DEVICE           "gateway-01"
#define SPLUNK_ROLE             "gateway"

/* ── Discovery protocol ──────────────────────────────────────────── */
#define SPLUNK_DISCOVER_PORT    9998
#define SPLUNK_DISCOVER_MSG     "PQC_SPLUNK_DISCOVER"
#define SPLUNK_DISCOVER_RESP    "PQC_SPLUNK_HOST:"
#define SPLUNK_DISCOVER_TIMEOUT 3   /* seconds per attempt */
#define SPLUNK_DISCOVER_TRIES   3   /* attempts before giving up */
#define SPLUNK_CONN_TIMEOUT     4   /* HEC send timeout seconds */

/* ── Runtime state ───────────────────────────────────────────────── */
static char   g_splunk_host[64]  = "";
static char   g_splunk_port[8]   = SPLUNK_HEC_PORT;
static bool   g_splunk_ready     = false;
static uint32_t g_splunk_fail_count = 0u;
static const uint32_t SPLUNK_MAX_CONSECUTIVE_FAILS = 5u;

/* ── Strip trailing whitespace / newline ─────────────────────────── */
static inline void splunk_strip_nl(char *s, size_t max_len)
{
    for (size_t i = 0; i < max_len && s[i]; ++i) {
        if (s[i] == '\r' || s[i] == '\n' || s[i] == ' ') {
            s[i] = '\0';
            return;
        }
    }
}


/*
 * Some Wi-Fi/AP combinations do not forward 255.255.255.255 broadcasts.
 * To keep Splunk IP auto-discovery working without hardcoding the PC IP,
 * also send discovery to the local /24 directed broadcast address.
 * Example: board IP 10.60.81.1 -> directed broadcast 10.60.81.255.
 */
static inline bool splunk_get_directed_broadcast(struct in_addr *out_addr)
{
    if (!out_addr) return false;

    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return false;

    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_port   = htons(53);
    remote.sin_addr.s_addr = inet_addr("8.8.8.8");

    /* UDP connect does not send a packet; it lets lwIP choose local IP. */
    if (connect(s, (struct sockaddr *)&remote, sizeof(remote)) != 0) {
        close(s);
        return false;
    }

    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    memset(&local, 0, sizeof(local));

    if (getsockname(s, (struct sockaddr *)&local, &len) != 0) {
        close(s);
        return false;
    }
    close(s);

    uint32_t ip = ntohl(local.sin_addr.s_addr);
    if (ip == 0u || ((ip >> 24) & 0xffu) == 127u) return false;

    /* BL602 demo networks normally use /24 DHCP masks. */
    uint32_t directed = (ip & 0xFFFFFF00u) | 0x000000FFu;
    out_addr->s_addr = htonl(directed);
    return true;
}


/*
 * Fallback: use the DHCP default gateway as the Splunk host.
 * This keeps Splunk IP automatic when the laptop is the Wi-Fi hotspot/gateway.
 * If the gateway is a phone/router and Splunk runs on a different client, this
 * fallback cannot work; use laptop-hotspot mode or allow UDP discovery.
 */
static inline bool splunk_get_default_gateway_host(char *out_host, size_t out_len)
{
    if (!out_host || out_len == 0) return false;

    if (netif_default == NULL) {
        return false;
    }

    uint32_t gw_net = netif_default->gw.addr;
    if (gw_net == 0u) {
        return false;
    }

    uint32_t gw = ntohl(gw_net);
    unsigned long a = (unsigned long)((gw >> 24) & 0xffu);
    unsigned long b = (unsigned long)((gw >> 16) & 0xffu);
    unsigned long c = (unsigned long)((gw >> 8) & 0xffu);
    unsigned long d = (unsigned long)(gw & 0xffu);

    if (a == 0u || a == 127u) {
        return false;
    }

    snprintf(out_host, out_len, "%lu.%lu.%lu.%lu", a, b, c, d);
    return true;
}

static inline void splunk_print_ipv4(const char *label, uint32_t net_ip)
{
    uint32_t ip = ntohl(net_ip);
    printf("%s%lu.%lu.%lu.%lu\r\n", label,
           (unsigned long)((ip >> 24) & 0xffu),
           (unsigned long)((ip >> 16) & 0xffu),
           (unsigned long)((ip >> 8) & 0xffu),
           (unsigned long)(ip & 0xffu));
}

/*
 * splunk_discover() — broadcast on LAN, wait for discovery server reply
 * Returns true if a Splunk server was located and g_splunk_host is set.
 */
static inline bool splunk_discover(void)
{
#ifdef SPLUNK_STATIC_HOST
    /* Static override — skip broadcast discovery */
    strncpy(g_splunk_host, SPLUNK_STATIC_HOST, sizeof(g_splunk_host) - 1);
    strncpy(g_splunk_port, SPLUNK_HEC_PORT, sizeof(g_splunk_port) - 1);
    printf("[Splunk] Using static host: %s:%s\r\n", g_splunk_host, g_splunk_port);
    return true;
#else
    for (uint8_t attempt = 0; attempt < SPLUNK_DISCOVER_TRIES; ++attempt) {
        /* ── Create UDP socket ─────────────────────────────────── */
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            printf("[Splunk] discover: socket() failed\r\n");
            continue;
        }

        /* Enable broadcast */
        int bval = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bval, sizeof(bval));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &bval, sizeof(bval));

        /* Receive timeout */
        struct timeval tv;
        tv.tv_sec  = SPLUNK_DISCOVER_TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        /* Bind to any port so we can receive the reply */
        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        local.sin_family      = AF_INET;
        local.sin_port        = 0;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
            printf("[Splunk] discover: bind() failed\r\n");
            close(sock);
            continue;
        }

        /* ── Send discovery packets ────────────────────────────── */
        const char *discover_msg = SPLUNK_DISCOVER_MSG;

        /* 1) Limited broadcast: 255.255.255.255 */
        struct sockaddr_in bcast;
        memset(&bcast, 0, sizeof(bcast));
        bcast.sin_family      = AF_INET;
        bcast.sin_port        = htons(SPLUNK_DISCOVER_PORT);
        bcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        sendto(sock, discover_msg, strlen(discover_msg), 0,
               (struct sockaddr *)&bcast, sizeof(bcast));

        /* 2) Directed subnet broadcast, for APs that drop 255.255.255.255 */
        struct in_addr directed_addr;
        if (splunk_get_directed_broadcast(&directed_addr)) {
            bcast.sin_addr = directed_addr;
            sendto(sock, discover_msg, strlen(discover_msg), 0,
                   (struct sockaddr *)&bcast, sizeof(bcast));
            splunk_print_ipv4("[Splunk] discover: directed broadcast ", directed_addr.s_addr);
        }

        printf("[Splunk] discover: broadcast attempt %u sent\r\n", (unsigned)(attempt + 1));

        /* ── Wait for reply ────────────────────────────────────── */
        char resp[128];
        memset(resp, 0, sizeof(resp));
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);

        int n = recvfrom(sock, resp, sizeof(resp) - 1, 0,
                         (struct sockaddr *)&from, &fromlen);
        close(sock);

        if (n <= 0) {
            printf("[Splunk] discover: no response (attempt %u)\r\n",
                   (unsigned)(attempt + 1));
            continue;
        }

        /* ── Parse "PQC_SPLUNK_HOST:<ip>:<port>" ──────────────── */
        const char *prefix = SPLUNK_DISCOVER_RESP;
        const size_t prefix_len = strlen(prefix);
        if ((size_t)n < prefix_len ||
            strncmp(resp, prefix, prefix_len) != 0) {
            printf("[Splunk] discover: bad response '%.40s'\r\n", resp);
            continue;
        }

        char *rest = resp + prefix_len;
        splunk_strip_nl(rest, sizeof(resp) - prefix_len);

        char *colon = strchr(rest, ':');
        if (colon) {
            /* Has explicit port: ip:port */
            const size_t ip_len = (size_t)(colon - rest);
            if (ip_len == 0 || ip_len >= sizeof(g_splunk_host)) {
                continue;
            }
            memcpy(g_splunk_host, rest, ip_len);
            g_splunk_host[ip_len] = '\0';
            strncpy(g_splunk_port, colon + 1, sizeof(g_splunk_port) - 1);
            splunk_strip_nl(g_splunk_port, sizeof(g_splunk_port));
        } else {
            /* IP only, use default port */
            strncpy(g_splunk_host, rest, sizeof(g_splunk_host) - 1);
            strncpy(g_splunk_port, SPLUNK_HEC_PORT, sizeof(g_splunk_port) - 1);
        }

        if (g_splunk_host[0] == '\0') {
            continue;
        }

        printf("[Splunk] Auto-discovered Splunk server at %s:%s\r\n",
               g_splunk_host, g_splunk_port);
        return true;
    }

    printf("[Splunk] Auto-discovery failed after %d attempts\r\n",
           SPLUNK_DISCOVER_TRIES);
    return false;
#endif /* SPLUNK_STATIC_HOST */
}

static inline bool splunk_token_configured(void)
{
    return SPLUNK_HEC_TOKEN[0] != '\0';
}

/*
 * splunk_send_event() — send one structured JSON event to Splunk HEC
 *
 * Parameters:
 *   event_type : e.g. "AEAD_AUTH_FAIL", "MSG_DECRYPTED", "WIFI_CONNECTED"
 *   severity   : "info", "low", "medium", "high", "critical"
 *   action     : free-form descriptor, e.g. "packet_rejected"
 *
 * Best-effort, non-blocking for the CoAP loop: if the send fails the
 * function prints a warning and returns without blocking.
 * After SPLUNK_MAX_CONSECUTIVE_FAILS consecutive failures the sender
 * re-runs discovery once to handle IP changes (e.g. Splunk host restart).
 */
static inline void splunk_send_event(
    const char *event_type,
    const char *severity,
    const char *action)
{
    static bool token_warned = false;
    if (!splunk_token_configured()) {
        if (!token_warned) {
            printf("[Splunk] disabled: SPLUNK_HEC_TOKEN not set at build time\r\n");
            token_warned = true;
        }
        return;
    }

    /* ── Discover server if not yet known ─────────────────────────── */
    if (!g_splunk_ready || g_splunk_host[0] == '\0') {
        if (!splunk_discover()) {
            return; /* no server found — give up silently */
        }
        g_splunk_ready    = true;
        g_splunk_fail_count = 0u;
    }

    /* ── Re-discover after repeated failures ──────────────────────── */
    if (g_splunk_fail_count >= SPLUNK_MAX_CONSECUTIVE_FAILS) {
        printf("[Splunk] Re-running discovery after %lu failures\r\n",
               (unsigned long)g_splunk_fail_count);
        g_splunk_ready    = false;
        g_splunk_host[0]  = '\0';
        g_splunk_fail_count = 0u;
        if (!splunk_discover()) {
            return;
        }
        g_splunk_ready = true;
    }

    /* ── Build JSON body ──────────────────────────────────────────── */
    char body[512];
    int body_len = snprintf(body, sizeof(body),
        "{"
          "\"index\":\"%s\","
          "\"source\":\"%s\","
          "\"sourcetype\":\"%s\","
          "\"event\":{"
            "\"event_type\":\"%s\","
            "\"severity\":\"%s\","
            "\"action\":\"%s\","
            "\"device_id\":\"%s\","
            "\"role\":\"%s\""
          "}"
        "}",
        SPLUNK_INDEX,
        SPLUNK_SOURCE,
        SPLUNK_SRCTYPE,
        event_type,
        severity,
        action,
        SPLUNK_DEVICE,
        SPLUNK_ROLE);

    if (body_len <= 0 || body_len >= (int)sizeof(body)) {
        return;
    }

    /* ── Build HTTP POST ──────────────────────────────────────────── */
    char request[768];
    int req_len = snprintf(request, sizeof(request),
        "POST /services/collector/event HTTP/1.1\r\n"
        "Host: %s:%s\r\n"
        "Authorization: Splunk %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        g_splunk_host,
        g_splunk_port,
        SPLUNK_HEC_TOKEN,
        body_len,
        body);

    if (req_len <= 0 || req_len >= (int)sizeof(request)) {
        return;
    }

    /* ── DNS resolve ──────────────────────────────────────────────── */
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(g_splunk_host, g_splunk_port, &hints, &res) != 0 || !res) {
        printf("[Splunk] DNS resolve failed for %s\r\n", g_splunk_host);
        g_splunk_fail_count++;
        return;
    }

    /* ── TCP connect ──────────────────────────────────────────────── */
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        g_splunk_fail_count++;
        return;
    }

    struct timeval tv;
    tv.tv_sec  = SPLUNK_CONN_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        printf("[Splunk] Connect failed to %s:%s\r\n",
               g_splunk_host, g_splunk_port);
        close(sock);
        freeaddrinfo(res);
        g_splunk_fail_count++;
        return;
    }
    freeaddrinfo(res);

    /* ── Send HTTP POST ───────────────────────────────────────────── */
    send(sock, request, req_len, 0);

    /* ── Read response ────────────────────────────────────────────── */
    char resp[256];
    memset(resp, 0, sizeof(resp));
    recv(sock, resp, sizeof(resp) - 1, 0);
    close(sock);

    if (strstr(resp, "200") || strstr(resp, "\"code\":0")) {
        printf("[Splunk] OK -> %s [%s]\r\n", event_type, severity);
        g_splunk_fail_count = 0u;
    } else {
        printf("[Splunk] WARN -> %.80s\r\n", resp);
        g_splunk_fail_count++;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* SPLUNK_HEC_H */
