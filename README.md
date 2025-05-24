# Wi-Fi Scanner using libnl

This program is a C example that demonstrates how to scan for Wi-Fi networks using the `libnl` library (specifically `libnl-genl` and the `nl80211` interface). It identifies a specified wireless interface, triggers a scan, and then attempts to dump and print the scan results, including BSSID, frequency, signal strength, and SSID of detected networks.

## Dependencies

To compile and run this program, you will need the following development libraries installed:

*   `libnl-3-dev`
*   `libnl-genl-3-dev`

On Debian-based systems (like Ubuntu), you can install them using:

```bash
sudo apt-get update
sudo apt-get install libnl-3-dev libnl-genl-3-dev
```

## Compilation

A Makefile is provided for easy compilation. Simply run:

```bash
make
```

This will produce an executable named `wifi_scan`.

## Execution

To run the program, you need to specify the wireless interface you want to scan on.
**Important:** Accessing the nl80211 interface for scanning typically requires root privileges. Therefore, you will usually need to run the program with `sudo`.

```bash
sudo ./wifi_scan <interface_name>
```

For example, if your wireless interface is `wlan0`:

```bash
sudo ./wifi_scan wlan0
```

The program will then print the nl80211 family ID, the index of the specified interface, trigger a scan, request scan results, and output details for each detected BSS (Basic Service Set).

### Example Output (will vary based on your environment):

```
nl80211 family ID: 26
Interface index for wlan0: 3
Scanning on interface: wlan0
Scan triggered.
Waiting for scan results... (this might take a few seconds)
Scan dump request sent.
Listening for scan results...

--- Found BSS ---
BSSID: 11:22:33:44:55:66
Frequency: 2412 MHz
Signal: -55.00 dBm
Status: 0 (Other)
SSID: MyHomeNetwork

--- Found BSS ---
BSSID: aa:bb:cc:dd:ee:ff
Frequency: 5200 MHz
Signal: -67.50 dBm
Status: 0 (Other)
SSID: AnotherNetwork-5G
Finished processing scan results.
```

## Notes

*   The program includes basic error handling. If it fails at a certain step, it will print an error message to `stderr`.
*   The parsing of Information Elements (IEs) for SSID extraction is a simplified example.
*   This version uses multicast notifications (NL80211_CMD_NEW_SCAN_RESULTS event) to detect scan completion before fetching the full results, which is a more robust approach than simple timed dumps.
*   Further improvements for production could include more comprehensive IE parsing and even more sophisticated error handling.
