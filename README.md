# PyNetscan
TUI network scanning tool written in Python

Nothing to install. Just download the netscan.py file, make it executable, and run it.

./netscan.py -h
usage: netscan.py [-h] [-n NETWORK]
netscan - simple LAN scanner (TUI)

options:
  -h, --help            show this help message and exit
  -n NETWORK, --network NETWORK
                        Subnet in CIDR notation, e.g. 172.16.88.0/24

While running you can press e to export to a csv file.
Enter to go into details of a device and see various details on the device such as open ports.

If you want to scan for different ports, open up the file and edit the line near the top to scan for other ports at PORT_CHECK_LIST = []
