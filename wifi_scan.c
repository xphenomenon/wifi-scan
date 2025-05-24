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
/* #include <netlink/error.h> // For nl_geterror() */

struct callback_data {
    struct nl_sock *sock;       // Netlink socket for sending messages from callback
    int nl80211_id;             // nl80211 family ID
    int ifindex;                // Interface index
    int scan_event_processed;   // Flag: 1 if NL80211_CMD_NEW_SCAN_RESULTS event has been processed
    int dump_requested;         // Flag: 1 if NL80211_CMD_GET_SCAN (dump) has been sent
};

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
    struct callback_data *cb_data = (struct callback_data *)arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = nlmsg_data(nlh);

    // Handle NLMSG_DONE to stop processing after a dump
    if (nlh->nlmsg_type == NLMSG_DONE) {
        if (cb_data->dump_requested) {
            printf("Callback: Scan dump complete (NLMSG_DONE received).\n");
            cb_data->dump_requested = 0; // Reset flag
        } else {
            // This might happen if NLMSG_DONE is received unexpectedly
            // printf("Callback: NLMSG_DONE received unexpectedly.\n");
        }
        return NL_STOP; // Stop nl_recvmsgs_default loop
    }

    // Check if it's an nl80211 command
    if (nlh->nlmsg_type != cb_data->nl80211_id) {
        // Not an nl80211 message, can skip or log
        // printf("Callback: Received non-nl80211 message type %d\n", nlh->nlmsg_type);
        return NL_OK;
    }

    // If it's the initial "scan finished" event
    if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS && !cb_data->scan_event_processed) {
        printf("Callback: Scan finished event (NL80211_CMD_NEW_SCAN_RESULTS) received. Requesting dump of results.\n");
        cb_data->scan_event_processed = 1; // Mark event as processed

        struct nl_msg *dump_msg = nlmsg_alloc();
        if (!dump_msg) {
            fprintf(stderr, "Callback: Failed to allocate message for scan dump\n");
            return NL_SKIP; // Or NL_STOP if it's critical
        }

        if (!genlmsg_put(dump_msg, NL_AUTO_PORT, NL_AUTO_SEQ, cb_data->nl80211_id, 0,
                         NLM_F_REQUEST | NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0)) {
            fprintf(stderr, "Callback: Failed to put genlmsg for get scan dump\n");
            nlmsg_free(dump_msg);
            return NL_SKIP; // Or NL_STOP
        }

        if (nla_put_u32(dump_msg, NL80211_ATTR_IFINDEX, cb_data->ifindex) != 0) {
            fprintf(stderr, "Callback: Failed to add ifindex attribute for scan dump\n");
            nlmsg_free(dump_msg);
            return NL_SKIP; // Or NL_STOP
        }

        int ret = nl_send_auto(cb_data->sock, dump_msg); // dump_msg is consumed by nl_send_auto
        if (ret < 0) {
            fprintf(stderr, "Callback: Failed to send get scan dump message: %s\n", strerror(-ret));
            // No nlmsg_free here, nl_send_auto handles it.
            // Depending on the error, we might want to NL_STOP.
            return NL_SKIP;
        }
        cb_data->dump_requested = 1; // Indicate that GET_SCAN has been sent
        printf("Callback: Scan dump request sent successfully.\n");
        return NL_OK; // Continue to receive messages (i.e., the dump results)
    }

    // If a dump has been requested and this is an NL80211_CMD_NEW_SCAN_RESULTS message,
    // it's a BSS entry from the dump.
    if (cb_data->dump_requested && gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
        // Existing BSS parsing logic (from the previous version of this function) goes here:
        struct nlattr *tb[NL80211_ATTR_MAX + 1];
        struct nlattr *bss_tb[NL80211_BSS_MAX + 1];
        char ssid_str[128] = {0};
        char mac_addr_str[18];

        if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                      genlmsg_attrlen(gnlh, 0), NULL) < 0) {
            fprintf(stderr, "Callback: Failed to parse top-level netlink attributes for BSS entry\n");
            return NL_SKIP;
        }

        if (!tb[NL80211_ATTR_BSS]) {
            // This might happen for non-BSS messages within the dump or if something is wrong.
            // For a simple dumper, we might just ignore it if it's not a BSS.
            // fprintf(stderr, "Callback: BSS attribute missing in dump message for type %d, cmd %d.\n", nlh->nlmsg_type, gnlh->cmd);
            return NL_OK;
        }

        if (nla_parse_nested(bss_tb, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], NULL)) {
            fprintf(stderr, "Callback: Failed to parse nested BSS attributes\n");
            return NL_SKIP;
        }

        printf("\n--- Found BSS (from dump) ---\n");

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
            printf("Signal: %.2f dBm\n", (float)nla_get_s32(bss_tb[NL80211_BSS_SIGNAL_MBM]) / 100.0);
        }
        
        if (bss_tb[NL80211_BSS_STATUS]) {
            uint32_t status_val = nla_get_u32(bss_tb[NL80211_BSS_STATUS]);
            printf("Status: %u (", status_val);
            if (status_val == NL80211_BSS_STATUS_ASSOCIATED) printf("Associated");
            else if (status_val == NL80211_BSS_STATUS_AUTHENTICATED) printf("Authenticated");
            else if (status_val == NL80211_BSS_STATUS_IBSS_JOINED) printf("IBSS Joined");
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
        // End of BSS parsing logic
    } else if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS && cb_data->scan_event_processed && !cb_data->dump_requested) {
        // This case means we got the scan_finished_event, processed it, but the dump request inside the callback failed.
        // The main loop should ideally detect this state via cb_data flags.
        // No specific action here other than possibly logging.
        printf("Callback: Received NEW_SCAN_RESULTS but dump was not successfully requested.\n");
    }
    // else {
    //    printf("Callback: Received unhandled nl80211 command %d (nlmsg_type %d)\n", gnlh->cmd, nlh->nlmsg_type);
    // }

    return NL_OK; // Continue processing messages
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
    
    // Disable sequence number checking for multicast messages
    nl_socket_disable_seq_check(sk);

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
    printf("nl80211 family ID: %d\n", nl80211_id); // Re-added this line as per instruction context

    // Resolve "scan" Multicast Group ID
    int mc_scan_id = 0;
    mc_scan_id = genl_ctrl_resolve_grp(sk, "nl80211", "scan");
    if (mc_scan_id < 0) {
        fprintf(stderr, "Failed to resolve nl80211 'scan' multicast group ID: %s\n", strerror(-mc_scan_id));
        nl_socket_free(sk);
        return 1;
    }
    printf("nl80211 'scan' multicast group ID: %d\n", mc_scan_id);

    // Subscribe to Multicast Group
    int ret_mc = nl_socket_add_memberships(sk, mc_scan_id, 0);
    if (ret_mc < 0) {
        fprintf(stderr, "Failed to subscribe to 'scan' multicast group: %s\n", strerror(-ret_mc));
        nl_socket_free(sk);
        return 1;
    }
    printf("Successfully subscribed to 'scan' multicast group.\n");

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

    struct callback_data cb_data = {
        .sock = sk,
        .nl80211_id = nl80211_id,
        .ifindex = ifindex,
        .scan_event_processed = 0,
        .dump_requested = 0
    };

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
    // printf("Waiting a moment for scan to initiate...\n"); // Removed, new loop has its own message

    // Register callback before sending trigger scan
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, scan_results_handler, &cb_data);
    nl_socket_modify_cb(sk, NL_CB_ACK, NL_CB_CUSTOM, scan_results_handler, &cb_data);
    nl_socket_modify_cb(sk, NL_CB_FINISH, NL_CB_CUSTOM, scan_results_handler, &cb_data);

    // New Main Receive Loop with Timeout
    printf("Waiting for scan finished event...\n");
    int recv_ret;
    int timeout = 10000; // 10 seconds timeout
    nl_socket_set_nonblocking(sk);
    
    struct timeval tv;
    fd_set readfds;
    int fd = nl_socket_get_fd(sk);
    int received_something = 0;
    
    // Loop while the scan event hasn't been processed OR 
    // while a dump has been requested but hasn't completed.
    while (!cb_data.scan_event_processed || cb_data.dump_requested) {
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;
        
        int select_ret = select(fd + 1, &readfds, NULL, NULL, &tv);
        if (select_ret < 0) {
            fprintf(stderr, "Main: select() error: %s\n", strerror(errno));
            break;
        } else if (select_ret == 0) {
            fprintf(stderr, "Main: Timeout waiting for scan results (%d ms)\n", timeout);
            break;
        }
        
        if (FD_ISSET(fd, &readfds)) {
            recv_ret = nl_recvmsgs_default(sk);
            if (recv_ret < 0) {
                if (recv_ret == -NLE_AGAIN) {
                    continue; // No message yet, loop again if within timeout
                } else if (recv_ret == NL_STOP) {
                    printf("Main: Receiver stopped by callback (NL_STOP), likely scan dump complete.\n");
                    if (cb_data.dump_requested) cb_data.dump_requested = 0;
                    break;
                } else {
                    fprintf(stderr, "Main: nl_recvmsgs_default error: %s\n", nl_geterror(recv_ret));
                    break;
                }
            }
            received_something = 1;
        }
    }
    
    if (!received_something) {
        fprintf(stderr, "Main: No messages received during timeout period.\n");
    }

    // After the loop, check the final state of flags
    if (!cb_data.scan_event_processed) {
        fprintf(stderr, "Main: Scan finished event was not received or failed to process.\n");
    } else if (cb_data.scan_event_processed && !cb_data.dump_requested && !(recv_ret == NL_STOP && !cb_data.dump_requested)) {
        // This condition means:
        // scan event was processed (so dump *should* have been requested)
        // AND dump_requested is FALSE (meaning sending dump_msg failed in callback)
        // AND it's not the case that we stopped normally after a successful dump (where dump_requested would be reset by NL_STOPPED logic)
        fprintf(stderr, "Main: Scan dump request may have failed in callback, or no BSS entries found after dump.\n");
    }
    printf("Main: Finished listening for scan results.\n");

    nl_socket_free(sk); // Cleanup socket
    return 0;
}
