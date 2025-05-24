#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <netlink/attr.h> // Needed for nla_parse, nla_data, etc.
// Include netlink/error.h for nl_perror if that was the choice,
// but sticking to fprintf and strerror for now.

static void parse_ies(unsigned char *ies, int ies_len, char *ssid_buf, size_t ssid_buf_len) {
    ssid_buf[0] = '\0'; // Initialize to empty string
    int i = 0;
    while (i < ies_len - 1) { // Must have at least ID and length fields (2 bytes)
        unsigned char id = ies[i];
        unsigned char len = ies[i+1];
        
        // Check for malformed IE (length byte indicates overflow or is too short)
        if (len == 0 && id != 0) { // Allow zero-length SSID for hidden, but other IEs must have some length if present
            i += 2; // move to next IE
            continue;
        }
        if (i + 1 + len >= ies_len) { 
            // fprintf(stderr, "Malformed IE: id=%u, len=%u, ies_len=%d, current_pos=%d\n", id, len, ies_len, i);
            break; 
        }

        if (id == 0) { // Element ID 0 is SSID
            // Ensure len is reasonable for SSID (max 32) and fits buffer
            size_t copy_len = len;
            if (copy_len > 32) copy_len = 32; // Max SSID length
            if (copy_len >= ssid_buf_len) copy_len = ssid_buf_len - 1; // Ensure space for null terminator

            memcpy(ssid_buf, &ies[i+2], copy_len);
            ssid_buf[copy_len] = '\0';
            // SSID found, can break if you only need SSID.
            break; 
        }
        i += 2 + len; // Move to the next IE
    }
}

// Forward declaration for a helper function to parse IEs
static void parse_ies(unsigned char *ies, int ies_len, char *ssid_buf, size_t ssid_buf_len);

static int scan_results_handler(struct nl_msg *msg, void *arg) {
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    // Correctly get the generic netlink header:
    // The payload of the netlink message (nlmsg_data(nlh)) IS the generic netlink header.
    struct genlmsghdr *gnlh = nlmsg_data(nlh);

    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *bss_tb[NL80211_BSS_MAX + 1];
    char ssid_str[128] = {0}; // Buffer for SSID, ensure it's enough (SSID max 32 chars)
    char mac_addr_str[18]; // For BSSID: XX:XX:XX:XX:XX:XX + null

    // Parse the top-level attributes from the generic netlink message
    // The attributes start after the generic netlink header (gnlh).
    // genlmsg_attrdata gets a pointer to the first attribute
    // genlmsg_attrlen gets the length of the attribute area
    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL) < 0) {
        // Added error check for nla_parse
        fprintf(stderr, "Failed to parse top-level netlink attributes\n");
        return NL_SKIP;
    }


    if (!tb[NL80211_ATTR_BSS]) {
        // This can happen, e.g. if the scan found nothing or message is not a result dump
        // Or if it's a NLMSG_DONE message at the end of a dump.
        // Check nlmsg_type if more specific handling is needed.
        // For now, just indicate if BSS is missing when expected.
        // fprintf(stderr, "BSS attribute missing from scan results message type %d\n", nlh->nlmsg_type);
        return NL_OK; // NL_OK to continue processing other messages in a multi-message response
    }

    // NL80211_ATTR_BSS is a nested attribute containing BSS information
    if (nla_parse_nested(bss_tb, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], NULL)) {
        fprintf(stderr, "Failed to parse nested BSS attributes\n");
        return NL_SKIP;
    }

    printf("\n--- Found BSS ---\n");

    if (bss_tb[NL80211_BSS_BSSID]) {
        unsigned char *mac = nla_data(bss_tb[NL80211_BSS_BSSID]);
        snprintf(mac_addr_str, sizeof(mac_addr_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        printf("BSSID: %s\n", mac_addr_str);
    }

    if (bss_tb[NL80211_BSS_FREQUENCY]) {
        printf("Frequency: %u MHz\n", nla_get_u32(bss_tb[NL80211_BSS_FREQUENCY]));
    }

    if (bss_tb[NL80211_BSS_SIGNAL_MBM]) {
        // Signal is in mBm (100 * dBm)
        printf("Signal: %.2f dBm\n", (float)nla_get_s32(bss_tb[NL80211_BSS_SIGNAL_MBM]) / 100.0);
    }
    
    if (bss_tb[NL80211_BSS_STATUS]) {
        uint32_t status = nla_get_u32(bss_tb[NL80211_BSS_STATUS]);
        printf("Status: %u (", status);
        if (status == NL80211_BSS_STATUS_ASSOCIATED) printf("Associated");
        else if (status == NL80211_BSS_STATUS_AUTHENTICATED) printf("Authenticated");
        else if (status == NL80211_BSS_STATUS_IBSS_JOINED) printf("IBSS Joined");
        else printf("Other");
        printf(")\n");
    }

    if (bss_tb[NL80211_BSS_INFORMATION_ELEMENTS]) {
        unsigned char *ies_data = nla_data(bss_tb[NL80211_BSS_INFORMATION_ELEMENTS]);
        int ies_len = nla_len(bss_tb[NL80211_BSS_INFORMATION_ELEMENTS]);
        parse_ies(ies_data, ies_len, ssid_str, sizeof(ssid_str));
        if (ssid_str[0] != '\0') {
            printf("SSID: %s\n", ssid_str);
        } else {
            printf("SSID: (hidden or not found)\n");
        }
    }

    return NL_OK; // Important to return NL_OK to continue processing dump messages
}

static int get_ifindex(const char *ifname) {
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("Failed to get interface index");
        // In a real application, you might exit or return an error code
        // For this example, we'll print an error and return 0,
        // which nl80211 often treats as an invalid/wildcard index,
        // or rely on main to exit.
    }
    return ifindex;
}

int main(int argc, char **argv) {
    // Basic argument check for interface name
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface_name>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1]; // Moved ifname declaration earlier

    struct nl_sock *sk = NULL;
    int nl80211_id = 0;
    int err;

    // Allocate Netlink Socket
    sk = nl_socket_alloc();
    if (!sk) {
        fprintf(stderr, "Failed to allocate netlink socket\n");
        return 1;
    }

    // Connect to Generic Netlink
    err = genl_connect(sk);
    if (err < 0) {
        fprintf(stderr, "Failed to connect to generic netlink: %s\n", strerror(-err));
        nl_socket_free(sk);
        return 1;
    }

    // Resolve nl80211 Family ID
    nl80211_id = genl_ctrl_resolve(sk, "nl80211");
    if (nl80211_id < 0) {
        fprintf(stderr, "Failed to resolve nl80211 family ID: %s\n", strerror(-nl80211_id));
        nl_socket_free(sk);
        return 1;
    }

    // Get interface index
    int ifindex = 0;
    ifindex = get_ifindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Could not find interface %s\n", ifname);
        nl_socket_free(sk);
        return 1;
    }
    printf("Interface index for %s: %d\n", ifname, ifindex);
    // printf("nl80211 family ID: %d\n", nl80211_id); // Already have this, can be removed if noisy
    // printf("Scanning on interface: %s\n", ifname); // Already have this

    struct nl_msg *msg = NULL;
    int ret;

    // 1. Trigger Scan
    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message for trigger scan\n");
        nl_socket_free(sk);
        return 1;
    }

    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0,
                     NLM_F_REQUEST | NLM_F_ACK, NL80211_CMD_TRIGGER_SCAN, 0)) {
        fprintf(stderr, "Failed to put genlmsg for trigger scan\n");
        nlmsg_free(msg);
        nl_socket_free(sk);
        return 1;
    }

    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) != 0) {
        fprintf(stderr, "Failed to add ifindex attribute for trigger scan\n");
        nlmsg_free(msg);
        nl_socket_free(sk);
        return 1;
    }

    ret = nl_send_auto(sk, msg); // msg is consumed by nl_send_auto
    if (ret < 0) {
        fprintf(stderr, "Failed to send trigger scan message: %s\n", strerror(-ret));
        nl_socket_free(sk);
        return 1;
    }
    // Not freeing msg here as nl_send_auto has consumed it.
    printf("Scan triggered.\n");
    // In a real application, wait for NL80211_CMD_NEW_SCAN_RESULTS event or use a timeout.
    // For simplicity, we proceed directly to fetching results. A small delay might be needed
    // on some systems if scans are not immediately available. sleep(2); // e.g.
    printf("Waiting a moment for scan to initiate...\n");


    // 2. Register Callback for Scan Results
    // The third argument is type, NL_CB_VALID means call for valid messages.
    // The fourth argument is func, our handler.
    // The fifth argument is arg, passed to the handler (NULL here).
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, scan_results_handler, NULL);

    // 3. Get Scan Dump
    msg = nlmsg_alloc(); // Re-allocate for the new message
    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message for get scan dump\n");
        nl_socket_free(sk);
        return 1;
    }

    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0,
                     NLM_F_REQUEST | NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0)) {
        fprintf(stderr, "Failed to put genlmsg for get scan dump\n");
        nlmsg_free(msg);
        nl_socket_free(sk);
        return 1;
    }

    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) != 0) {
        fprintf(stderr, "Failed to add ifindex attribute for get scan dump\n");
        nlmsg_free(msg);
        nl_socket_free(sk);
        return 1;
    }

    ret = nl_send_auto(sk, msg); // msg is consumed
    if (ret < 0) {
        fprintf(stderr, "Failed to send get scan dump message: %s\n", strerror(-ret));
        nl_socket_free(sk);
        return 1;
    }
    // Not freeing msg here.
    printf("Scan dump request sent.\n");

    // 4. Receive Messages
    int recv_ret;
    printf("Listening for scan results...\n");
    while ((recv_ret = nl_recvmsgs_default(sk)) > 0) {
        // Callback scan_results_handler is processing messages
        // Loop continues as long as messages are processed successfully
    }
    if (recv_ret < 0) {
        // Check if the error is NL_STOP, which means our callback stopped processing.
        // This is not an error in itself if the callback decided to stop.
        // However, other negative values are actual errors.
        if (recv_ret != -NLE_STOP) { // NLE_STOP is libnl's equivalent for NL_STOP from callback
             fprintf(stderr, "nl_recvmsgs_default failed: %s (%d)\n", strerror(-recv_ret), -recv_ret);
             nl_socket_free(sk);
             return 1;
        }
    }
    printf("Finished processing scan results.\n");

    nl_socket_free(sk); // Cleanup socket
    return 0;
}
