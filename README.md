# CSE351-assignment-4
CSE351: Computer Networks | Fall 2025 | Programming Assignment 4 | Simple IP Router

This project implements a virtual IP router in a Mininet-based network environment. The router processes raw Ethernet frames and supports packet forwarding, ARP resolution, ICMP message generation, and IP packet filtering.

The implementation focuses on router logic, including forwarding decisions, ARP cache management, routing table lookup, and firewall functionality.

## Features

* Ethernet frame processing
* IPv4 packet forwarding
* Longest Prefix Match (LPM) routing
* ARP request and reply handling
* ARP cache management
* ICMP error message generation
* ICMP echo reply support (ping)
* Firewall-style IP blacklist filtering
* TTL decrement and checksum recomputation
* Compatible with the provided Mininet test environment

## Repository Structure

```text
.
├── CSE351_PA4.pdf      # Assignment specification
├── README.md           # Repository documentation
├── report.pdf          # assignment report
├── sr_router.c         # Router forwarding and ICMP logic
└── sr_arpcache.c       # ARP cache and ARP request handling
```

## Implemented Functions

### sr_router.c

#### sr_handlepacket()

Main packet-processing function responsible for:

* Ethernet frame validation
* IPv4 packet processing
* Packet forwarding
* Longest Prefix Match routing
* TTL handling
* ICMP generation
* ARP interactions
* Firewall filtering

#### ip_black_list()

Implements packet filtering functionality.

* Blocks packets matching configured blacklist entries
* Filters both inbound and outbound traffic
* Logs blocked IP addresses

### sr_arpcache.c

#### sr_arpcache_handle_arpreq()

Handles queued ARP requests.

* Sends ARP requests periodically
* Retransmits requests approximately once per second
* Removes expired requests
* Generates ICMP Host Unreachable messages after five failed ARP attempts

## Supported Protocols

### Ethernet

* Ethernet frame parsing
* Source and destination MAC address handling
* Packet forwarding between interfaces

### IPv4

* Header validation
* Checksum verification
* TTL decrement
* Checksum recomputation
* Routing table lookup using Longest Prefix Match

### ARP

* ARP request processing
* ARP reply processing
* ARP cache lookup
* ARP cache updates
* Queuing packets awaiting address resolution

### ICMP

Implemented ICMP messages:

| Type | Code | Description                     |
| ---- | ---- | ------------------------------- |
| 0    | 0    | Echo Reply                      |
| 3    | 0    | Destination Network Unreachable |
| 3    | 1    | Destination Host Unreachable    |
| 3    | 3    | Port Unreachable                |
| 11   | 0    | Time Exceeded                   |

## Forwarding Logic

For packets not destined for the router:

1. Verify packet validity and checksum.
2. Apply blacklist filtering.
3. Decrement TTL.
4. Recompute IP checksum.
5. Perform Longest Prefix Match routing lookup.
6. Resolve next-hop MAC address through ARP cache.
7. Forward packet or generate ARP request if necessary.

## Testing Environment

The router is designed to run inside the provided virtual network environment using:

* Ubuntu 20.04
* Mininet
* POX Controller
* Stanford Simple Router framework

Typical connectivity tests include:

* `ping`
* `traceroute`
* `wget`

## Main Functionality

The implementation enables:

* Communication between hosts across multiple networks
* Dynamic ARP resolution
* Correct ICMP responses
* Routing table based forwarding
* Packet filtering through IP blacklisting
* Recovery from unreachable hosts and expired ARP requests


## Development Environment

This project was developed using the provided CSE351 virtual machine and the Stanford Simple Router framework.

The router was tested in a Mininet-based virtual network environment using:

- Ubuntu 20.04
- Mininet
- POX Controller
- Stanford Simple Router framework

Only the required source files modified for the assignment are included in this repository.
