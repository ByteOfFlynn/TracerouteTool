# ICMP Traceroute Tool

This project is a custom-built traceroute utility implemented using raw sockets and ICMP messages in Python. It traces the path of packets across a network to a specified destination, displaying the IP addresses of intermediate routers and measuring round-trip times (RTT) at each hop.

Built from the ground up without relying on third-party libraries, the traceroute leverages ICMP Echo Requests and handles multiple ICMP response types to provide a low-level, accurate look at the route taken by packets across the internet.

## Features

-  **Traceroute Functionality**
  - Sends ICMP Echo Requests with incrementing TTL values
  - Displays each hop’s IP address and round-trip time
  - Gracefully handles unreachable destinations and timeouts

-  **Intelligent ICMP Parsing**
  - Identifies and interprets ICMP response types:
    - Type 0: Echo Reply
    - Type 3: Destination Unreachable
    - Type 11: Time Exceeded
  - Converts ICMP error codes into human-readable messages

-  **RTT Statistics**
  - Tracks and displays:
    - Minimum RTT
    - Maximum RTT
    - Average RTT
    - Packet loss percentage

-  **Validation & Debugging**
  - Verifies integrity of ICMP response packets:
    - Identifier match
    - Sequence number match
    - Payload match
  - Debug output shows expected vs actual values for full traceability

## How It Works

1. For each hop (starting with TTL=1), the program sends an ICMP Echo Request.
2. Each router that decrements TTL to 0 replies with an ICMP Time Exceeded message.
3. This continues until the final destination replies with an ICMP Echo Reply.
4. The tool extracts IP addresses, calculates RTT, and compiles a report of the full route.

## Technologies Used

- **Python 3**
- **Raw Sockets**
- **ICMP Protocol (RFC 792)**
