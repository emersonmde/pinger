#!/usr/bin/env python3
"""
Uses ICMP Echo Request to ping a host, or trace the hops to a host.

Copyright (c) 2018 Matthew Emerson

Version 1.4
"""

import os, sys, socket, struct, select, time, argparse

def checksum(data):
    """
    Calculate the 16 bit checksum for data
    
    Described in http://www.faqs.org/rfcs/rfc1071.html as the "the 16-bit 1's complement sum is computed over the octets
        concerned, and the 1's complement of this sum is placed in the
        checksum field"
    """
    total = 0
    # Sum 16 bits chunks (the first byte * 256 + second byte)
    for i in range(len(data) - (len(data) % 2)):
        total += (data[i] << 8) if i % 2 else data[i]
    
    # Add in any remaining bits
    if len(data) % 2 != 0:
        total + data[-1]

    # Add in carry bits
    total = (total & 0xffff) + (total >> 16)
    total = total + (total >> 16)

    # Flip and change order
    total = ~total & 0xffff
    return total >> 8 | (total << 8 & 0xff00)

    # Flip
    #return (~total) & 0xffff

def recv_ping(icmp_socket, dest_addr, id, timeout):
    """Receive a single ICMP packet"""
    while True:
        start_time = time.time()
        ready = select.select([icmp_socket], [], [], timeout)
        time_in_select = (time.time() - start_time)

        if ready[0] == []:
            # Timeout
            return None, None

        time_received = time.time()

        packet, addr = icmp_socket.recvfrom(1024)
        icmp_header = packet[20:28]
        type, code, checksum, packet_id, seq = struct.unpack('BBHHH', icmp_header)
        if addr[0] == dest_addr:
            # Unpack our the start_time we sent in the original packet
            size_of_double = struct.calcsize('d')
            time_sent = struct.unpack('d', packet[28:28 + size_of_double])[0]
            rtt = time_received - time_sent
            return rtt, addr[0]
        elif type == 11: # Time exceeded message (TTL)
            # If we're using traceroute, calculate the start time ourselves since it wont be sent back
            rtt = time_received - start_time
            return rtt, addr[0]

        timeout -= time_in_select

def send_ping(icmp_socket, dest_addr, id, seq):
    """Send a single ICMP Echo Request (Control message 8, code 0)"""
    # Zero out checksum to build header
    cs = 0
    
    # Header: type 8, code 8, checksum 16, identifier 16, sequence 16
    # Use calculate header + data in order to calculate checksum
    header = struct.pack('BBHHH', 8, 0, cs, id, seq)

    # Add start time to calculate RTT
    data = struct.pack('d', time.time())

    # Calculate checksum and repack header with the correct checksum
    cs = checksum(header + data)
    header = struct.pack('BBHHH', 8, 0, socket.htons(cs), id, seq)
    packet = header + data

    # Make it so
    icmp_socket.sendto(packet, (dest_addr, 1))

def ping(dest, count = 3, timeout = 1):
    """Send count number of ICMP Echo Requests to a destination"""
    try:
        icmp_proto = socket.getprotobyname('icmp')
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
        # Set IP TTL (really only used for traceroute)
        icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, 64)
        dest_addr = socket.gethostbyname(dest)
    except socket.error as msg:
        print('Socket error: %s' % msg)
        print('Requires root to create ICMP socket')
        exit(1)

    id = os.getpid() & 0xffff

    print('Pinging %s' % dest)
    for i in range(count):
        try:
            send_ping(icmp_socket, dest_addr, id, i)
            rtt, _addr = recv_ping(icmp_socket, dest_addr, id, timeout)
        except socket.error as msg:
            print('Socket error: %s' % msg)
            exit(1)
        if rtt is None:
            print('Request timeout for icmp_seq %i' % i)
        else:
            print('Received from %s: icmp_seq=%d time=%0.4f ms' % (dest_addr, i, (rtt * 1000)))

def traceroute(dest, count = 3, timeout = 1, hops = 64):
    """Trace the route to the destination using ICMP Echo Requests and limiting IP TTL to get each router to send us a Time Exceeded response"""
    try:
        icmp_proto = socket.getprotobyname('icmp')
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
        dest_addr = socket.gethostbyname(dest)
    except socket.error as msg:
        print('Socket error: %s' % msg)
        exit(1)

    id = os.getpid() & 0xffff

    hop_addr = ''
    hop = ''
    print('traceroute to %s (%s), %d hops max' % (dest, dest_addr, hops))
    # Increment the IP TTL (starting at 1) to systematically receive Time Exceeded responses from each hop
    for i in range(1, hops):
        try:
            # Set IP TTL
            icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, i)
            # Used to collect RTT from each hop
            total_rtt = []
            for j in range(count):
                send_ping(icmp_socket, dest_addr, id, i)
                rtt, hop_addr = recv_ping(icmp_socket, dest_addr, id, timeout)
                total_rtt.append(rtt)
        except socket.error as msg:
            print('Socket error: %s' % msg)
            exit(1)

        try:
            # Try to get the hostname from the responder
            hop = socket.gethostbyaddr(hop_addr)[0]
        except:
            hop = hop_addr

        print('%s (%s)  ' % (hop, hop_addr), end='')
        for t in total_rtt:
            if t is None:
                print('\t*', end='', flush=True)
            else:
                print('\t%0.4f ms' % (t * 1000), end='', flush=True)
        print('\n', end='', flush=True)
        if hop_addr == dest_addr:
            break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="An ICMP ping/traceroute utility. Requires root to create ICMP socket.")
    parser.add_argument("destination", help="The ip address or hostname of the destination.")
    parser.add_argument("-c", "--count", help="Count of ICMP packets to be sent to the destination. The defaults is 3.", type=int, default=3)
    parser.add_argument("-t", "--timeout", help="Timeout in seconds. The default is 1 second.", type=int, default=1)
    parser.add_argument("--traceroute", help="Trace hops to the destination.", action="store_true")
    args = parser.parse_args()

    if args.traceroute:
        traceroute(args.destination, args.count, args.timeout)
    else:
        ping(args.destination, args.count, args.timeout)
