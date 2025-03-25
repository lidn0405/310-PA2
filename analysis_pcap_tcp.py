import dpkt
import sys
import socket

f = open('assignment2.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

senderIP = '130.245.145.12'
receiverIP = '128.208.2.198'

flows = []

trackNext = False
lastPacket = False
temp = 0
transactions = {}
transaction_handler = {} #[firstTwoCount, rcvWindow]
timestamps = {} #[timestamp, total_packet_length]

scale = 0
throughput = 0

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data

    # Get TCP Flow
    # Check if it's a SYN but not ACK packet 
    if (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
        flows.append((tcp.sport, socket.inet_ntoa(ip.src), tcp.dport, socket.inet_ntoa(ip.dst)))
        
        # Find the Receiver Window Size from the options
        tcpOpts = dpkt.tcp.parse_opts(tcp.opts)

        for option, data in tcpOpts:
            if option == dpkt.tcp.TCP_OPT_WSCALE:
                scale = int.from_bytes(data)

        # Get initial timestamp
        timestamps[tcp.sport] = [ts, 0]
    
    # Get first two transactions
    # Checks if it's a SYN and ACK packet
    if (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK):
        trackNext = True
        continue

    # Ensure sender ACK creates new instance of port
    # Probably could've used dport but I just thought of it (I cry)
    if trackNext:
        transaction_handler[tcp.sport] = [2]
        # Create an array to store two transactions
        transactions[tcp.sport] = []
        trackNext = False

    # Checks if packet is first two and from sender
    if tcp.sport in transaction_handler and transaction_handler[tcp.sport][0] > 0:
        # Checks if packet has data in case piggy back
        if len(tcp.data) > 0:
            # print(f"TCP OPT WSCALE : {dpkt.tcp.TCP_OPT_WSCALE}")
            recWindow = tcp.win * 2**dpkt.tcp.TCP_OPT_WSCALE
            transaction_handler[tcp.sport].append(tcp.win * 2**(scale))
            transactions[tcp.sport].append((tcp.seq, tcp.ack, transaction_handler[tcp.sport][1]))
            transaction_handler[tcp.sport][0] -= 1

    # Get Sender Throughput
    if tcp.sport in timestamps:
        timestamps[tcp.sport][1] += len(tcp)

    # Calculate Throughput
    # Check if destination of FIN is sender
    if tcp.flags & dpkt.tcp.TH_FIN and tcp.dport in timestamps:
        lastPacket = True
        # Check if the next ACK after FIN is from sender
        temp = tcp.dport
        continue

    if tcp.flags & dpkt.tcp.TH_ACK and lastPacket and tcp.sport in timestamps and temp == tcp.sport:
        timePeriod = ts - timestamps[tcp.sport][0]
        throughput = timestamps[tcp.sport][1] / timePeriod
        timestamps[tcp.sport].append(throughput)
        timestamps[tcp.sport].append(timePeriod)
        # print(f"Port: {tcp.sport} Time Period: {timePeriod} Throughput: {throughput}")
        lastPacket = False
        temp = 0



# Print Part A
for i in range(len(flows)):
    portNum = flows[i][0]
    print(f"Flow {i+1} Information: {flows[i]}")
    print(f"Transaction 1: Seq#: {transactions.get(portNum)[0][0]} ACK: {transactions.get(portNum)[0][1]} Receive Window Size: {transactions.get(portNum)[0][2]}")
    print(f"Transaction 2: Seq#: {transactions.get(portNum)[1][0]} ACK: {transactions.get(portNum)[1][1]} Receive Window Size: {transactions.get(portNum)[1][2]}")
    print(f"Throughput: {timestamps[portNum][2]} Total Data: {timestamps[portNum][1]} Time Period: {timestamps[portNum][3]}")
    print()

    
