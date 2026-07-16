# PyNetScan

A standalone Linux network scanner with an interactive terminal interface, written in Python.

PyNetScan discovers devices, scans TCP ports, optionally probes UDP services, identifies hostnames and manufacturers, collects basic service information, and displays the results in a searchable TUI.

## Features

* Single standalone Python file
* Interactive terminal user interface
* Automatic local subnet detection
* Custom CIDR network scanning
* ARP discovery on directly connected networks
* ICMP and TCP fallback discovery
* Routed-network scanning
* Quick, Standard, Deep, Full, Discovery, and Custom scan profiles
* Custom TCP port lists and ranges
* Optional response-based UDP probes
* Concurrent host and port scanning
* Live scan progress, elapsed time, rate, and estimated completion
* Scan cancellation with partial results retained
* Reverse DNS, NetBIOS, mDNS, and SSDP discovery
* MAC address manufacturer lookup
* Basic operating-system estimation
* Estimated device-type classification
* Basic service and banner detection
* Security review indicators for potentially risky services
* Search, filtering, and sorting
* Individual-device rescanning
* Device aliases
* Full-subnet refresh and change comparison
* CSV and JSON exports
* Large-scan safety warnings

## Installation

PyNetScan does not require a traditional installation. Download the single `netscan.py` file, make it executable, and run it.

```bash
wget https://raw.githubusercontent.com/flattery103/PyNetscan/main/netscan.py
chmod +x netscan.py
./netscan.py
```

You can also run it through Python:

```bash
python3 netscan.py
```

## Requirements

PyNetScan is designed for Linux and requires:

* Python 3
* The Linux `ip` command
* A terminal with curses support

Most Linux distributions already include these components.

### Optional mDNS support

mDNS discovery uses the optional Python `zeroconf` module.

Install it with:

```bash
python3 -m pip install --user zeroconf
```

PyNetScan will continue to work without `zeroconf`, but mDNS names and services will not be collected.

## Root privileges

PyNetScan can run without root privileges.

Without root access, it falls back to ICMP and TCP-based discovery when raw ARP or raw ICMP sockets are unavailable.

For the best discovery results on a directly connected network, run it with `sudo`:

```bash
sudo ./netscan.py
```

Root privileges improve ARP and ICMP discovery but are not required for normal TCP scanning.

## Starting PyNetScan

Run PyNetScan without arguments to open the scan-profile menu:

```bash
./netscan.py
```

PyNetScan attempts to detect the local subnet automatically.

You can specify a network manually:

```bash
./netscan.py --network 192.168.1.0/24
```

## Scan profiles

### Discover

Find responsive devices without performing a general TCP port scan.

```bash
./netscan.py --profile discover
```

### Quick

Scan a smaller set of commonly used TCP services.

```bash
./netscan.py --profile quick
```

### Standard

Scan a broad set of common TCP services. This is the recommended general-purpose profile.

```bash
./netscan.py --profile standard
```

### Deep

Scan TCP ports 1 through 1024, selected higher-value ports, and collect basic service and banner information.

```bash
./netscan.py --profile deep
```

### Full

Scan all TCP ports from 1 through 65535.

```bash
./netscan.py --profile full
```

The older `--all-ports` option is also supported:

```bash
./netscan.py --all-ports
```

Full scans can take a considerable amount of time and generate substantial network traffic.

### Custom

Scan a custom list of TCP ports or port ranges:

```bash
./netscan.py --ports 22,80,443,3389
```

Ranges are supported:

```bash
./netscan.py --ports 1-1024,3389,8000-8100
```

You can also explicitly select the Custom profile:

```bash
./netscan.py --profile custom --ports 22,80,443,8000-8100
```

## UDP probes

UDP scanning is optional and separate from TCP scanning.

```bash
sudo ./netscan.py \
  --profile standard \
  --udp-ports 53,123,137,161,1900
```

UDP results are listed as **responded**, not definitively open.

A UDP service may be open but remain silent. A missing response can also indicate packet filtering. PyNetScan therefore does not label silent UDP ports as closed or open.

## Common examples

Scan the automatically detected subnet with the Standard profile:

```bash
./netscan.py --profile standard
```

Scan a specific network:

```bash
./netscan.py \
  --network 192.168.50.0/24 \
  --profile standard
```

Run a fast scan:

```bash
./netscan.py \
  --network 192.168.50.0/24 \
  --profile quick
```

Run a Deep scan with banner detection:

```bash
sudo ./netscan.py \
  --network 192.168.50.0/24 \
  --profile deep
```

Enable banner detection with the Standard profile:

```bash
./netscan.py \
  --profile standard \
  --banners
```

Scan selected TCP and UDP ports:

```bash
sudo ./netscan.py \
  --network 192.168.50.0/24 \
  --ports 22,53,80,443,445,3389 \
  --udp-ports 53,123,161
```

Use a specific network interface:

```bash
sudo ./netscan.py \
  --network 192.168.50.0/24 \
  --interface ens18
```

Run the Standard profile without displaying the startup menu:

```bash
./netscan.py --no-menu
```

Automatically export JSON after the scan:

```bash
./netscan.py \
  --profile standard \
  --json
```

Specify an export filename:

```bash
./netscan.py \
  --profile standard \
  --output office-network-scan
```

## Command-line options

```text
usage: netscan.py [-h] [-n NETWORK]
                  [--profile {discover,quick,standard,deep,full,custom}]
                  [-a] [-p PORTS] [--udp-ports UDP_PORTS]
                  [--interface INTERFACE] [--timeout TIMEOUT]
                  [--concurrency CONCURRENCY]
                  [--port-concurrency PORT_CONCURRENCY]
                  [--no-dns] [--no-mdns] [--no-ssdp]
                  [--banners] [--output OUTPUT] [--json]
                  [--force] [--no-menu] [--update-oui]
                  [--no-oui] [--version]

PyNetScan - standalone Linux network scanner with a TUI

options:
  -h, --help
      Show the help message and exit.

  -n, --network NETWORK
      Subnet in CIDR notation, such as 192.168.1.0/24.

  --profile {discover,quick,standard,deep,full,custom}
      Select a scan profile and skip the startup profile menu.

  -a, --all-ports
      Scan all TCP ports from 1 through 65535. Equivalent to
      --profile full.

  -p, --ports PORTS
      Custom TCP ports or ranges, such as
      22,80,443,8000-8100.

  --udp-ports UDP_PORTS
      Optional response-based UDP probes, such as
      53,123,137,161,1900.

  --interface INTERFACE
      Network interface to use, such as ens18.

  --timeout TIMEOUT
      TCP and UDP timeout in seconds. Default: 0.5.

  --concurrency CONCURRENCY
      Maximum number of hosts processed concurrently.
      Default: 200.

  --port-concurrency PORT_CONCURRENCY
      Maximum number of concurrent TCP connection attempts.
      Default: 800.

  --no-dns
      Disable reverse DNS lookups.

  --no-mdns
      Disable mDNS discovery.

  --no-ssdp
      Disable SSDP discovery.

  --banners
      Enable basic service and banner detection.

  --output OUTPUT
      Preferred export filename or base path.

  --json
      Automatically export JSON after scanning.

  --force
      Skip large-scan confirmation.

  --no-menu
      Use the Standard profile without opening the startup menu.

  --update-oui
      Force an update of the IEEE manufacturer database.

  --no-oui
      Disable MAC address manufacturer lookups.

  --version
      Display the PyNetScan version and exit.
```

## TUI keyboard controls

### Device list

| Key                 | Action                                |
| ------------------- | ------------------------------------- |
| Up / Down           | Select a device                       |
| Page Up / Page Down | Move through the device list          |
| Enter               | Open details for the selected device  |
| `/`                 | Search the current results            |
| `x`                 | Clear the current search              |
| `f`                 | Cycle through result filters          |
| `o`                 | Cycle through sort modes              |
| `r`                 | Refresh the entire subnet             |
| `s`                 | Rescan only the selected device       |
| `a`                 | Add, change, or remove a device alias |
| `e`                 | Export results to CSV                 |
| `j`                 | Export results to JSON                |
| `?`                 | Open the help screen                  |
| `q`                 | Quit                                  |

### Device details

| Key                 | Action                           |
| ------------------- | -------------------------------- |
| Up / Down           | Scroll through details           |
| Page Up / Page Down | Scroll one page                  |
| Home / End          | Jump to the beginning or end     |
| `p`                 | Ping the selected device         |
| `s`                 | Rescan the selected device       |
| `a`                 | Add, change, or remove its alias |
| `b`                 | Return to the device list        |
| `q`                 | Quit                             |

### During a scan

Press `q` to cancel the active scan.

PyNetScan keeps the partial results gathered before cancellation so they can still be reviewed or exported.

## Search, filters, and sorting

Search can match:

* IP address
* Device name or alias
* MAC address
* Manufacturer
* Operating-system guess
* Device type
* Open port

Press `f` to cycle through these filters:

* All devices
* Devices with open or responding ports
* Devices with services requiring review
* Changed devices
* New devices
* Offline devices

Press `o` to cycle through available sort modes, including:

* IP address
* Device name
* Manufacturer
* Operating-system guess
* Number of detected ports
* Change status

## Refresh and change tracking

Press `r` to scan the subnet again.

PyNetScan compares the new scan with the previous results and identifies:

* New devices
* Returning devices
* Devices that no longer respond
* Newly detected TCP ports
* TCP ports that are no longer detected
* Newly responding UDP ports
* UDP ports that stopped responding
* Changed names, MAC addresses, or device information

Result symbols include:

```text
+  New device
*  Changed device
-  Offline device
!  Service may require security review
```

## Device aliases

Press `a` while a device is selected to add or change its alias.

Aliases are stored in:

```text
~/.config/netscan/aliases.json
```

Entering a blank alias removes the saved alias.

## Manufacturer database

PyNetScan uses the IEEE OUI database to identify device manufacturers from MAC addresses.

The local cache is stored in:

```text
~/.cache/netscan/oui.json
```

The database is refreshed automatically when it becomes outdated.

Force an update with:

```bash
./netscan.py --update-oui
```

Disable manufacturer lookups with:

```bash
./netscan.py --no-oui
```

If the database cannot be downloaded, PyNetScan continues scanning without manufacturer information.

## Exports

Press `e` to export CSV or `j` to export JSON.

By default, PyNetScan creates timestamped filenames such as:

```text
pynetscan_192.168.1.0-24_2026-07-16_143500.csv
pynetscan_192.168.1.0-24_2026-07-16_143500.json
```

CSV exports include fields such as:

* IP address
* Status and detected changes
* Device name and type
* MAC address and manufacturer
* Operating-system guess
* Discovery method
* TCP ports
* Responding UDP ports
* Security review items
* Service banners
* mDNS information
* SSDP information

JSON exports also include scan settings, timestamps, route information, warnings, and structured device details.

Use `--output` to choose a filename or base path:

```bash
./netscan.py \
  --profile standard \
  --output scans/office-network
```

This produces the applicable extension:

```text
scans/office-network.csv
scans/office-network.json
```

## Large scans

PyNetScan warns before starting scans that involve unusually large networks or very high numbers of connection attempts.

A Full scan of an entire `/24` network can involve more than 16 million TCP connection attempts and may take a considerable amount of time.

Use `--force` only when you understand the size and impact of the requested scan:

```bash
sudo ./netscan.py \
  --network 192.168.1.0/24 \
  --profile full \
  --force
```

Consider scanning a smaller address range or a targeted list of ports whenever possible.

## Detection limitations

PyNetScan provides useful network inventory information, but several results are estimates.

### Operating-system guesses

Operating-system identification is primarily based on the TTL from an ICMP response.

Firewalls, routers, virtualization, and customized network stacks can make these guesses inaccurate.

Devices discovered only through TCP are reported as having an unknown operating system unless a real ICMP TTL was received.

### Device types

Device types are estimated using available information such as:

* Open ports
* Manufacturer
* Hostname
* mDNS services
* SSDP information
* Service banners

These classifications should be treated as likely device types rather than definitive identification.

### Security review indicators

PyNetScan highlights services that may deserve review, such as:

* Telnet
* FTP
* SMB
* RDP
* VNC
* Database listeners
* Redis
* MongoDB
* Elasticsearch
* Docker API

A review indicator does not prove that a vulnerability exists. It means the detected service may warrant additional inspection or access-control verification.

### UDP probes

UDP results only show ports that returned a recognizable response. Silent UDP ports are not marked open or closed.

## Authorized use

Only scan networks and systems that you own or have explicit permission to test.

Network scanning can trigger monitoring systems, generate significant traffic, or violate organizational policies when performed without authorization.

## License

PyNetScan is licensed under the GNU General Public License version 3.

See the `LICENSE` file for the complete license text.
