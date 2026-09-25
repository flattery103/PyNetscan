# PyNetScan

A standalone Linux network scanner with an interactive terminal interface, written in Python.

**Version: 2.2.0**

PyNetScan discovers devices, scans TCP ports, optionally probes UDP services, identifies hostnames and manufacturers, collects basic service information, and displays the results in a searchable TUI.

Download one `netscan.py` file and run it. No application installation, database, or background service is required. Python, the Linux networking tools, and an interactive terminal are still needed.

This README describes the behavior of [netscan.py](netscan.py) in version 2.2.0. Run `python3 netscan.py --help` to view the options supported by your downloaded copy.

## Features

- Single standalone Python file with an interactive terminal interface
- Automatic local subnet detection and custom IPv4 CIDR targets
- ARP discovery on directly connected networks, with ICMP/TCP fallback when appropriate
- Discover, Quick, Standard, Deep, Full, and Custom scan profiles
- Custom TCP port lists and ranges, plus optional UDP probes
- Shared, bounded scan concurrency, adaptive timing, retries, and probe-rate controls
- Live progress, cancellation, and partial-result retention
- Explicit probe states and comparisons that distinguish current observations from last-known results
- Reverse DNS, NetBIOS, optional mDNS, and SSDP discovery
- MAC manufacturer lookup, OS estimates, device-type estimates, and basic service banners
- Search, filtering, sorting, single-device rescanning, and editable aliases
- CSV and JSON exports with state, timing, and completion information
- Large-scan warnings and confirmation

## What's new in 2.2.0

- **Redirect-aware web identification:** retain HTTP redirect destinations and inspect advertised HTTP/HTTPS endpoints, including nonstandard ports, within strict same-device limits.
- **Meraki local-page recognition:** recognize a `devices.meraki.direct` redirect whose embedded MAC matches the observed device MAC. Preserve the advertised hostname for HTTP Host and TLS SNI while connecting to the scanned IP. This can provide a vendor-based display name even if the destination page cannot be reached.
- **Useful, labeled display names:** recognized vendor/product page titles can support an inferred label. Generic login titles do not replace missing hostnames. Aliases and resolved names retain priority. A `~` marker in the list means the display name is inferred.
- **Automatic Standard/Deep web checks:** lightweight web identification now runs for these profiles without `--banners`. Other profiles can enable it with `--banners`; `--no-web-identification` explicitly disables web requests.
- **Manufacturer download fallback:** try IEEE first and Wireshark if the primary source fails. Validate publisher downloads, retain working caches, and support longest-prefix matches for 24-, 28-, and 36-bit assignments.
- **Identification provenance:** details and exports distinguish registry manufacturer data, inferred vendor, resolved name, advertised web hostname, attempted/answered endpoints, and lookup availability.

The probe states, partial-result handling, UDP validation, scheduling, and controls added in 2.1.0 remain. This update does not implement the other previously discussed DNS-queue, richer mDNS, SSDP-description, ICMP-OS, or expanded SNMP ideas.

Everything remains in the single `netscan.py` file. **No `curl`, Wireshark executable, or additional required Python package is needed.** The Wireshark fallback downloads a data file, not software.

## Installation

Download the script into the directory where you want to keep it:

```bash
wget https://raw.githubusercontent.com/flattery103/PyNetscan/main/netscan.py
chmod +x netscan.py
./netscan.py
```

You can also run it through Python:

```bash
python3 netscan.py
```

Check the version:

```bash
python3 netscan.py --version
```

## Requirements

PyNetScan is designed for Linux and IPv4 targets. It uses Python 3, the Linux `ip` command, and a terminal with Python curses support. Install the `ping` command for system-ping fallback and the device-details ping action.

Core scanning does not require a third-party Python package. mDNS uses optional `zeroconf`.

### Optional mDNS support

Install `zeroconf` for the Python interpreter that runs PyNetScan. On Debian, the distribution package is available as [python3-zeroconf](https://packages.debian.org/trixie/python3-zeroconf):

```bash
sudo apt update
sudo apt install python3-zeroconf
```

When already logged in as root, omit `sudo`. On other distributions, use the corresponding package or an isolated Python environment appropriate for that system.

Without this optional module, PyNetScan continues without mDNS results and reports a warning.

## Root privileges

PyNetScan can run without root. Raw ARP and raw ICMP require suitable permissions; normal TCP connection scanning does not.

For local-network discovery with raw-socket access:

```bash
sudo ./netscan.py
```

When already running as root:

```bash
./netscan.py
```

Container restrictions may still prevent raw-socket operations even when the process runs as root. Review the scanner's warnings rather than assuming that a scan has full raw-socket access.

Aliases and manufacturer caches are stored under the home directory of the account running the scanner. Running as root and running as a normal user can therefore use different saved files.

## Starting PyNetScan

Run without a profile or port selection to open the startup profile menu:

```bash
./netscan.py
```

Specify a target and profile to skip that menu:

```bash
./netscan.py --network 192.168.50.0/24 --profile standard
```

PyNetScan attempts to detect the local subnet when `--network` is omitted. If detection fails, it uses the configured fallback subnet in the script. Specify `--network` when the target must be unambiguous.

A single address can be selected with `/32`:

```bash
./netscan.py --network 192.168.50.12/32 --ports 22,443
```

**This release is interactive.** `--no-menu` skips the startup menu, and `--json` enables an initial automatic export; neither provides a headless scan-and-exit mode.

## Scan profiles

| Profile | Behavior |
| --- | --- |
| `discover` | Find responsive devices without a general TCP port scan. Discovery can still send ICMP and TCP probes. |
| `quick` | Check a smaller set of common TCP services. |
| `standard` | Check the broader built-in list of common TCP services and run lightweight web identification. |
| `deep` | Check TCP ports 1–1024 plus selected higher ports, web identification, and basic service greetings. |
| `full` | Check all TCP ports 1–65535 on selected hosts. This is not a full UDP scan. |
| `custom` | Check the TCP ports supplied with `--ports`. |

Examples:

```bash
./netscan.py --profile discover
./netscan.py --profile quick
./netscan.py --profile deep
./netscan.py --profile full
./netscan.py --profile custom --ports 22,80,443,8000-8100
```

`--all-ports` remains an alias for selecting all TCP ports. A port list can also be supplied without an explicit profile:

```bash
./netscan.py --ports 22,80,443,3389
./netscan.py --ports 1-1024,3389,8000-8100
```

Port ranges are inclusive. Port values must be within 1–65535. `--all-ports` takes precedence over `--ports`; otherwise an explicit `--ports` list overrides the profile's TCP list. A `deep` profile still enables banners when used with a custom list.

## Discovery controls

Directly connected networks use ARP when the necessary raw-socket access is available. Routed targets and fallback discovery use ICMP and selected TCP probes.

Both a successful TCP connection and an explicit refusal provide responsiveness evidence. A refusal does **not** mean the port is open, and an intermediary may have generated the response.

Select discovery ports:

```bash
./netscan.py \
  --network 192.168.50.0/24 \
  --profile standard \
  --discovery-ports 22,443,8443
```

`--discovery-ports` controls the TCP discovery probes, not the subsequent general port list. ARP discovery on a directly connected network does not use that TCP list as its primary discovery method.

To check every selected address without requiring discovery success:

```bash
./netscan.py \
  --network 192.168.50.0/24 \
  --ports 22,443,3389 \
  --skip-discovery
```

`--scan-all-targets` is an alias for `--skip-discovery`. Supply at least one TCP or UDP port with this mode. A target is not considered responsive merely because it was selected for scanning. Large-scan safeguards still apply.

## Web identification and redirects

Standard and Deep scans automatically inspect open ports in the built-in HTTP service set. They start with a small read-only HTTP/HTTPS request and retain the status, selected headers, page title, and redirect information. This is an additional identification stage, not a broad web crawl or authenticated audit.

```bash
./netscan.py --network 192.168.50.0/24 --profile standard
```

Quick, Custom, Full, and Discover do not automatically enable this stage. `--banners` enables it where an eligible open port was actually found; Discover has no general port scan to supply such ports.

```bash
./netscan.py --network 192.168.50.1/32 --ports 80,443 --banners
```

Disable HTTP identification, including redirects, explicitly:

```bash
./netscan.py --network 192.168.50.0/24 --profile standard --no-web-identification
```

`--no-web-identification` takes precedence over `--banners` for HTTP/HTTPS requests. Non-HTTP greetings can still run when banners are enabled.

### Scope and limits

- Follow at most **three redirect hops per chain**, with at most **eight web requests per host** and a **10-second web-work budget per host** after acquiring its web worker. Each request also has a shorter timeout. Scheduling and bounded connection cleanup are additional overhead.
- Limit response headers to **16 KiB** and sampled response bodies to **64 KiB**. Bodies are not saved; only selected identification information is retained. Encoded bodies that ignore the requested identity encoding are not parsed for titles.
- A literal-IP redirect must target the **same scanned IP**, not merely another address on the same subnet. A general DNS hostname must resolve exclusively to that scanned IPv4 address. Connections are pinned to that IP after the check so a second hostname lookup cannot change the destination.
- A MAC-matched Meraki local-status alias is a supported exception to requiring DNS resolution: the scanner still connects only to the scanned IP, using the advertised name for Host/SNI. An alias with a different MAC does not get this exception.
- Reject non-HTTP schemes, embedded URL credentials, invalid URLs, off-target redirects, redirect loops, and HTTPS-to-HTTP downgrade redirects. Do not send authentication credentials or propagate response cookies. No login attempts are made.
- An advertised redirect **can lead to a port outside the selected TCP scan list**. The read-only web stage may request that endpoint, but it records the observation separately and does not rewrite the original TCP scan scope or mark an untested port open in `tcp_results`.
- `--no-dns` disables reverse-name lookups; it does not disable the bounded forward lookup needed to validate general redirect hostnames. Disable web identification to prevent those redirect-related lookups and requests.
- Web requests are not included in `--max-rate`, which caps TCP/UDP discovery and port probes. They have their own bounded concurrency and limits.

For example, a redirect on TCP 80 may advertise HTTPS on TCP 8092 even when 8092 was not selected for a port scan. An HTTP response from that destination is recorded in `web_observations`; failure to reach it is recorded as a timeout/error, not proof of a closed port. The redirect itself remains useful evidence either way.

### Names and confidence

The `name` field is a display label, not necessarily a hostname. A `~` marker precedes inferred display names in the list. Details show `name_source`, `name_is_inferred`, the separately resolved name, and the evidence behind a vendor estimate.

An illustrative result is:

```text
Display Name:   Cisco Meraki device
Name Source:    Inferred: MAC-matched Meraki HTTP redirect
Resolved Name:  Not discovered
Vendor Guess:   Cisco Meraki
```

This does **not** reveal the configured dashboard name or exact model. A MAC-derived web hostname is kept as an advertised endpoint, not silently promoted to a configured hostname. Registry manufacturer information remains separate from a web-inferred vendor.

Recognized vendor/product titles currently include Cisco Meraki, Fortinet/FortiGate, Synology, and QNAP. Other titles remain visible as observations without automatically becoming a device name. Generic titles such as `Login` and generic `Server` headers do not establish identity.

### TLS limitations

HTTPS collection retains the existing inventory behavior of accepting unverified certificates; `tls_validation` explicitly reports `not_verified_inventory_only`. Preserving SNI is **not** certificate verification. No certificate-trust, hostname-validation, or vulnerability conclusion should be drawn from a successful request. Web identity information can be spoofed and is labeled as inference rather than authenticated identity.

The Meraki local-status behavior is documented by [Cisco Meraki](https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Troubleshooting_and_Support/Troubleshooting/Cisco_Meraki_Local_Status_Page_Security_and_SD-WAN).

## UDP probes

UDP scanning is optional and separate from TCP scanning:

```bash
./netscan.py \
  --network 192.168.50.0/24 \
  --profile standard \
  --udp-ports 53,123,137,1900
```

PyNetScan validates supported replies against the request and expected protocol. A verified reply is recorded as `responded`; a generic or unrecognized reply is recorded as `unverified_response` and is not listed as a verified UDP service.

| Port | Probe |
| --- | --- |
| `53/udp` | DNS question with response validation |
| `123/udp` | NTP request with response validation |
| `137/udp` | NetBIOS name-service request with structured parsing |
| `1900/udp` | SSDP discovery request with response validation |
| `161/udp` | Optional read-only SNMPv2c request requiring an explicitly supplied community |
| Other selected UDP ports | Generic datagram; replies remain unverified rather than proving a particular service |

No response does not establish that a UDP port is open or closed. An explicit refusal is recorded separately and can originate from an intermediary.

### Optional read-only SNMP

The SNMP probe requests `sysDescr.0` using SNMPv2c. It does not guess communities, use an implicit default community, perform writes, or implement SNMPv3.

Supply an authorized read-only community through an environment variable. For example, in Bash:

```bash
read -r -s -p "Read-only SNMP community: " NETSCAN_SNMP_COMMUNITY
printf '\n'
export NETSCAN_SNMP_COMMUNITY

./netscan.py \
  --network 192.168.50.0/24 \
  --profile standard \
  --udp-ports 161 \
  --snmp-community-env NETSCAN_SNMP_COMMUNITY

unset NETSCAN_SNMP_COMMUNITY
```

The command-line argument is the **variable name**, not the community itself. It must exist in the process that starts PyNetScan; take this into account when using `sudo`.

With no community option, a selected port 161 probe is skipped and marked `unsupported`. Naming a missing or empty environment variable produces an argument error. Credentials are excluded from exported scan settings. SNMPv2c does not provide encrypted transport; use it only where appropriate on authorized management networks.

## Timing, concurrency, and rate limits

The shared worker pool distributes work across active hosts. The default host limit is 200 and the requested global port-concurrency limit is 800. Available file descriptors may cause PyNetScan to reduce concurrency and show a warning. Concurrency limits are not a guarantee of a particular scan speed.

Timing adapts by default, starting at 0.5 seconds and using response measurements within a 0.1–2.0 second adaptive range. By default, a no-response probe can be retried once. Explicit refusals, local errors, and positive replies are not retried.

Use a fixed per-attempt timeout, a probe-rate cap, and one retry:

```bash
./netscan.py \
  --network 192.168.50.0/24 \
  --profile standard \
  --max-rate 200 \
  --max-retries 1 \
  --timeout 0.5
```

| Option | Meaning |
| --- | --- |
| `--max-rate N` | Maximum TCP/UDP probe starts per second, including TCP discovery and retries. Default `0` adds no rate cap. |
| `--max-retries N` | Extra attempts for no-response probes. Allowed range: `0`–`5`; default: `1`. |
| `--timeout N` | Fixed positive timeout in seconds for each attempt; disables adaptive timing. |
| `--no-adaptive-timeout` | Use a fixed 0.5-second timeout when `--timeout` is not supplied. |
| `--concurrency N` | Requested active-host limit. |
| `--port-concurrency N` | Requested global port-worker/connection budget. |

**`--max-rate` is not a total packet-rate limit.** ARP, ICMP, multicast discovery, name resolution, HTTP redirect/page requests, and other banner collection are separate traffic. A probe can also involve multiple packets.

## Common examples

Run a general inventory:

```bash
./netscan.py --network 192.168.50.0/24 --profile standard
```

Add service greetings to Standard's automatic web identification:

```bash
./netscan.py --network 192.168.50.0/24 --profile standard --banners
```

Request a particular interface for route selection and ARP:

```bash
./netscan.py --network 192.168.50.0/24 --interface ens18 --profile quick
```

**Interface limitation:** version 2.1.0 does not bind every TCP, UDP, ICMP, or multicast operation to the requested interface. Do not rely on `--interface` as an all-traffic isolation guarantee; verify routing on multi-interface or VPN systems.

Perform a small loopback check without optional discovery/enrichment:

```bash
./netscan.py \
  --network 127.0.0.1/32 \
  --ports 22,443 \
  --skip-discovery \
  --no-dns --no-mdns --no-ssdp --no-oui \
  --max-rate 10 --max-retries 0
```

Start the Standard profile without the startup menu:

```bash
./netscan.py --no-menu
```

## Command-line options

```text
usage: netscan.py [-h] [-n NETWORK]
                  [--profile {discover,quick,standard,deep,full,custom}] [-a]
                  [-p PORTS] [--udp-ports UDP_PORTS] [--interface INTERFACE]
                  [--timeout TIMEOUT] [--concurrency CONCURRENCY]
                  [--port-concurrency PORT_CONCURRENCY]
                  [--discovery-ports DISCOVERY_PORTS] [--skip-discovery]
                  [--max-rate MAX_RATE] [--max-retries MAX_RETRIES]
                  [--no-adaptive-timeout] [--snmp-community-env VARIABLE]
                  [--no-dns] [--no-mdns] [--no-ssdp] [--banners]
                  [--no-web-identification] [--output OUTPUT] [--json]
                  [--force] [--no-menu] [--update-oui] [--no-oui] [--version]

PyNetScan - standalone Linux network scanner with a TUI

options:
  -h, --help            show this help message and exit
  -n, --network NETWORK
                        Subnet in CIDR notation
  --profile {discover,quick,standard,deep,full,custom}
                        Scan profile; supplying this skips the startup profile
                        menu
  -a, --all-ports       Scan all TCP ports 1-65535 (equivalent to --profile
                        full)
  -p, --ports PORTS     Custom TCP ports/ranges, for example
                        22,80,443,8000-8100
  --udp-ports UDP_PORTS
                        Optional response-based UDP probes, for example
                        53,123,137,161,1900
  --interface INTERFACE
                        Network interface to use, for example ens18
  --timeout TIMEOUT     Fixed per-attempt TCP/UDP timeout; disables adaptive
                        timing (default starts at 0.5s)
  --concurrency CONCURRENCY
                        Concurrent hosts (default: 200)
  --port-concurrency PORT_CONCURRENCY
                        Total concurrent TCP attempts (default: 800)
  --discovery-ports DISCOVERY_PORTS
                        TCP discovery ports/ranges; an explicit refusal also
                        proves responsiveness
  --skip-discovery, --scan-all-targets
                        Scan every target even when discovery probes would
                        fail
  --max-rate MAX_RATE   Maximum TCP/UDP probe attempts/sec, including
                        discovery and retries (0: unlimited)
  --max-retries MAX_RETRIES
                        Retries for no-response probes only, 0-5 (default: 1)
  --no-adaptive-timeout
                        Use the default fixed timeout instead of adapting to
                        measured responses
  --snmp-community-env VARIABLE
                        Environment variable containing an explicitly supplied
                        read-only SNMPv2c community; never guessed
  --no-dns              Disable reverse DNS
  --no-mdns             Disable mDNS discovery
  --no-ssdp             Disable SSDP discovery
  --banners             Enable service greetings and web identification
  --no-web-identification
                        Disable HTTP identity/redirect requests (automatic for
                        Standard/Deep)
  --output OUTPUT       Preferred export filename or base path
  --json                Automatically export JSON after scanning
  --force               Skip large-scan confirmation
  --no-menu             Use the standard profile without a startup menu
  --update-oui          Force an IEEE OUI database refresh
  --no-oui              Disable manufacturer lookups
  --version             show program's version number and exit
```

`--no-dns` disables reverse DNS, not every naming mechanism. NetBIOS is separate, as are mDNS and SSDP with their own flags. Likewise, `--no-ssdp` disables multicast SSDP discovery; it does not remove an explicit `1900` from `--udp-ports`.

The device list prefixes inferred display names with `~`; open Details to see the source and supporting evidence.

## TUI keyboard controls

### Device list

| Key | Action |
| --- | --- |
| Up / Down | Select a device |
| Page Up / Page Down | Move through the list |
| Enter | Open device details |
| `/` | Search results |
| `x` | Clear the search |
| `f` | Cycle result filters |
| `o` | Cycle sort modes |
| `r` | Rescan the subnet and compare results |
| `s` | Rescan only the selected device |
| `a` | Add, change, or remove an alias |
| `e` | Export the report to CSV |
| `j` | Export the report to JSON |
| `?` | Open help |
| `q` | Quit |

### Device details

| Key | Action |
| --- | --- |
| Up / Down | Scroll details |
| Page Up / Page Down | Scroll one page |
| Home / End | Jump to the beginning or end |
| `p` | Ping the selected device |
| `s` | Rescan the selected device |
| `a` | Edit its alias |
| `b` | Return to the device list |
| `q` | Quit |

### During a scan

Press `q` to cancel. PyNetScan stops queued and active work, cleans up scan resources, and retains observations already collected. Remaining work is not silently treated as completed.

Details and exports record discovery, TCP, UDP, and identification completion separately. Cancelling also stops optional identification instead of requiring it to finish first.

## Search, filters, and sorting

Search is a case-insensitive text match across IP, name/alias, MAC, manufacturer, OS guess, device type, and currently observed TCP/verified UDP ports.

Press `f` to cycle through `all`, `open`, `review`, `changed`, `new`, `not_observed`, `partial`, and `errors`.

The `open` filter shows current open TCP ports or verified UDP responses, not historical-only ports. The `partial` filter includes incomplete and not-scanned devices. The `changed` filter includes hosts with comparison notes, including uncertainty notes.

Press `o` to sort by IP, name, manufacturer, OS, current port count, or status.

## Probe states

TCP and UDP observations are more detailed than a list of detected ports:

| State | Meaning |
| --- | --- |
| `open` | A TCP connection succeeded. This alone does not verify the application protocol. |
| `refused` | An explicit connection refusal was received. This is distinct from silence; an intermediary may generate it. |
| `no_response` | No accepted reply arrived before the configured attempts timed out. |
| `not_scanned` | No completed observation is recorded for the port, for example because it was out of scope or interrupted. |
| `error` | A probe failed with a reported local, socket, or routing error rather than a usable service result. |
| `responded` | A UDP reply passed the supported protocol checks. |
| `unverified_response` | A reply arrived but did not establish a verified supported UDP service. |
| `unsupported` | The requested probe could not be performed, such as SNMP without a supplied community. |

**A timeout, cancelled probe, or omitted port is not evidence that a service closed.**

## Refresh and change tracking

Press `r` to compare a new scan with the current report in the same running session. Press `s` for a single-device recheck.

Comparisons identify newly observed ports, explicitly refused ports, returning devices, and supported name/MAC changes. When a previously observed service cannot be reverified, it is retained in **last-known** fields rather than being presented as newly confirmed open or closed.

For example, if an earlier scan observed ports 22 and 443, and a new scan checks only 22 before cancellation, port 443 remains last-known. It is not reported closed merely because the new open-port list omits it.

Host statuses include:

| Status | Meaning |
| --- | --- |
| `CURRENT` | The host's available evidence and completion state qualify it as a current result. |
| `NEW` | A newly observed responsive device relative to the previous report, with the required stages complete. |
| `CHANGED` | A current result with comparison notes. Read the notes to distinguish observations from uncertainty. |
| `PARTIAL` | The result is incomplete, including interrupted scanning or identification. |
| `NOT_OBSERVED` | The device was not observed by the completed discovery checks that applied to it; this does not prove an outage. |
| `NOT_SCANNED` | The device was not conclusively checked, or is outside the new scan's scope. |
| `ERROR` | Discovery or probe errors affect the result. |

The initial scan has no earlier report to compare against. New-device marking is a comparison feature, not a label automatically applied to every first-scan row.

Result symbols:

```text
+  New device
*  Changed device
-  Not observed
?  Incomplete or not scanned
E  Error
!  Service deserves review; not proof of a vulnerability
```

Historical-only ports and carried-forward identity information are not new measurements. Last-observed times are separate from scan-completion times. Comparisons are in-memory; this release does not load a saved JSON baseline.

## Device aliases

Press `a` to add or change an alias. A blank value removes it.

Aliases are keyed by IP address and stored in:

```text
~/.config/netscan/aliases.json
```

The `~` directory belongs to the account running the scanner. For root, this is `/root`.

## Manufacturer database

PyNetScan first downloads the [IEEE assignment CSV](https://standards-oui.ieee.org/oui/oui.csv). If the request or validation fails, it tries the [Wireshark manufacturer data file](https://www.wireshark.org/download/automated/data/manuf.gz) over HTTPS. The fallback is not an executable or optional package dependency.

The downloader limits transfer size and time, rejects invalid/incomplete responses, and checks the parsed assignment count before replacing its cache. HTML error pages are not accepted as databases. Wireshark-format 24-, 28-, and 36-bit assignments use longest-prefix matching; exact unmasked device MAC entries are not generalized into vendor prefixes.

The cache remains:

```text
~/.cache/netscan/oui.json
```

A successful cache is reused for **30 days** by default, including after a fallback download. This avoids downloading it on every scan. Do not repeatedly force refreshes; the Wireshark publisher asks clients not to download its weekly dataset more often than needed.

```bash
./netscan.py --profile standard --update-oui
./netscan.py --profile standard --no-oui
```

These options apply when a scan runs; they are not separate update-and-exit commands. If both publishers fail, a usable earlier cache remains intact. Without one, the scan continues and reports that the database is unavailable. A missing MAC, unavailable database, disabled lookup, and no matching assignment are distinguished in host details and exports.

The cache records its publisher and format metadata. Existing 2.1.0 flat caches can be read; successful new downloads use cache format 2. If rolling back to a release that cannot read this format, move the generated cache aside and let that release rebuild it. Cache files are local runtime data, not files to commit to GitHub.

A manufacturer match identifies an address-block registrant, not an exact model or assigned hostname. Web-inferred vendor information is shown separately and does not overwrite the registry field.

## Exports

Press `e` for CSV or `j` for JSON. Exports contain the full report, not only the filtered rows visible on screen.

Default names include the subnet and export timestamp:

```text
pynetscan_192.168.1.0-24_2026-09-25_143500.csv
pynetscan_192.168.1.0-24_2026-09-25_143500.json
```

Choose a filename or base path with `--output`. Create the parent directory first:

```bash
mkdir -p scans
./netscan.py --profile standard --output scans/office-network
```

Pressing `e` writes `scans/office-network.csv`; pressing `j` writes `scans/office-network.json`.

**`--output` by itself does not trigger an export.** Add `--json` to automatically export after the initial scan, then remain in the TUI:

```bash
mkdir -p scans
./netscan.py --profile standard --output scans/office-network.json --json
```

Exports write to the selected path and can replace an existing file. Use distinct paths to retain older reports. Even default timestamped names can collide if exports of the same type occur within one second.

### CSV

The original inventory columns remain, with additional columns for reachability, last-seen time, host completion/cancellation, per-stage completion, requested port counts, probe-state summaries, last-known ports, and probe details. Version 2.2.0 appends Name Source, Name Inferred, Resolved Name, Vendor Inference, Identification Evidence, Web Identification Status, Web Observations, Manufacturer Lookup Status, and Manufacturer Source.

Existing consumers that assume an exact column count should be updated for the appended columns. The `TCP Ports` and `UDP Responded` columns contain current observations; last-known ports have separate columns.

### JSON

JSON retains **`schema_version: 2`** and adds optional identification fields without changing the existing probe-state encoding. It includes scan scope/settings, warnings, discovery outcomes, cancellation, and per-host observations.

New host fields include `name_source`, `name_is_inferred`, `resolved_name`, `vendor_guess`, `identification_evidence`, `web_observations`, `web_identification_status`, `manufacturer_lookup_status`, and `manufacturer_source`. Each web observation records its original target IP, advertised hostname, URL, scheme, port, outcome, received HTTP status, redirect handling, and relevant errors/limits. URL query values and fragments are not retained; credential-bearing URLs are rejected. Response cookies and raw page bodies are not saved.

Web observations from a missing device are cleared on refresh rather than being presented as fresh evidence. Retained names are labeled last-known when they were not reverified. A web-stage completion value means the bounded stage ended, not that the device supplied a name or model.

`tcp_results` and `udp_results` encode observations in `state_ranges`. Range strings use comma-separated ports and inclusive ranges, such as `22,80,443,8000-8010`. A missing port defaults to `not_scanned`, not `refused` or closed. Use the report's `tcp_ports` and `udp_ports` to determine the requested scope.

The compatibility field `open_udp_ports` contains verified UDP responders; it is not a conclusion about silent UDP ports. Credentials are not included in exported scan settings.

## Large scans

PyNetScan estimates scan work and warns about large address ranges or high attempt counts. The estimate includes discovery and retry work; optional web identification is a separately bounded stage. A full TCP scan across all usable addresses in a `/24` can exceed 16 million initial port checks before retries.

`--force` bypasses confirmation; it does not reduce the traffic or authorize the scan. Prefer a small target range and selected ports while validating settings.

## Detection limitations

### Operating-system guesses

OS estimates use observed ICMP TTLs and are not definitive fingerprints. A successful TCP-only discovery does not manufacture a TTL; without a real ICMP result, the OS remains unknown.

### Device types and service names

Device types are estimates based on available names, manufacturers, ports, and discovery information. Conventional service names beside port numbers are hints, not proof that the expected application is listening. Basic banners provide additional observations but are not comprehensive service or vulnerability checks.

### Identification and UDP

mDNS requires its optional library and appropriate network reachability. SSDP names are accepted from explicit friendly-name metadata, not arbitrary USN suffixes. This release does not fetch SSDP device-description URLs for friendly names.

UDP protocol validation distinguishes supported replies from generic or malformed responses. Silent or unverified services can be missed, so a missing verified UDP response is not evidence of closure.

### Security review indicators

Review markers identify services worth inspecting, not verified vulnerabilities, authentication weaknesses, or proof of encryption settings. Assess access controls and the actual service configuration separately.

### Scope and operation

This release supports IPv4 on Linux, requires an interactive terminal, and does not include saved-baseline loading, comprehensive certificate assessment, or guaranteed interface binding for every type of traffic.

## Authorized use

Only scan networks and systems that you own or have explicit permission to test. Use conservative targets and limits appropriate for the environment. Scans can trigger monitoring and create substantial traffic.

Reports can contain sensitive device names, addresses, and service information. Keep real network exports and credentials out of public repositories.

## License

PyNetScan is licensed under the GNU General Public License version 3. See [LICENSE](LICENSE) for the full license text.

