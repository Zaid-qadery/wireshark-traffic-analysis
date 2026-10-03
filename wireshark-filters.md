# Wireshark Filters I Used

## Finding hosts

| What it shows | Filter |
|---|---|
| ARP requests | `arp.opcode == 1` |
| ARP requests from one machine | `arp.opcode == 1 && arp.src.proto_ipv4 == 192.168.56.104` |
| Pings (echo requests) | `icmp.type == 8` |
| Ping replies | `icmp.type == 0` |

## Port scans

| What it shows | Filter |
|---|---|
| SYN without ACK (connection attempts / SYN scan) | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Closed port replies | `tcp.flags.reset == 1 && tcp.flags.ack == 1` |
| Open port replies | `tcp.flags.syn == 1 && tcp.flags.ack == 1` |
| All traffic between two machines | `ip.addr == 192.168.56.104 && ip.addr == 192.168.56.101` |
| SYNs with the Nmap-style window sizes | `tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size_value in {1024 2048 3072 4096}` |

## FTP

| What it shows | Filter |
|---|---|
| All FTP commands and replies | `ftp` |
| Usernames and passwords | `ftp.request.command == "USER" \|\| ftp.request.command == "PASS"` |
| Failed logins | `ftp.response.code == 530` |
| Successful logins | `ftp.response.code == 230` |
| File downloads | `ftp.request.command == "RETR"` |
| Passive mode replies (they contain the data port) | `ftp.response.code == 227` |
| The file data itself | `ftp-data` |

## Other useful bits

- **Statistics → Conversations** shows which machines are talking the most
- **Statistics → I/O Graphs** is good for spotting spikes like a port scan
- **Right-click a packet → Follow → TCP Stream** shows a whole FTP session in one window
