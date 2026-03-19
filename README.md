# PyNetscan
TUI network scanning tool written in Python

Nothing to install. Just download the netscan.py file, make it executable, and run it.

./netscan.py -h
usage: netscan.py [-h] [-n NETWORK] [-a] [-p PORTS]

netscan - simple LAN scanner (TUI)

options:
  -h, --help            show this help message and exit
  -n NETWORK, --network NETWORK
                        Subnet in CIDR notation, e.g. 172.16.88.0/24
  -a, --all-ports       Scan all TCP ports 1-65535 (very slow/noisy).
  -p PORTS, --ports PORTS
                        Comma-separated ports to scan (optional ranges allowed), e.g. 22,80,443 or 1-1024,3389

While running, you can press e to export to a csv file.
Enter to go into details of a device and see various details on the device such as open ports.
p while in details to ping

If you want to scan for different ports, open up the file and edit the line near the top to scan for other ports at PORT_CHECK_LIST = []

Scanning for all ports on a /24 took me a couple of hours, and it may seem like it isn't doing anything for stretches. 
Planning to add something to better indicate it is still running.
