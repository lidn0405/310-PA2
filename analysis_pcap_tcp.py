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

cwnd_handler = {}
port_rtt = {}
trackThisPacket = {} #[tcp.sport] = [True/False, index] (contains index of which cwnd)
initial_ts = {}


packetCount = 0
packet_ACK_handler = {}

packet_retransmit = {}

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data

    # Get TCP Flow
    # Check if it's a SYN but not ACK packet 
    if (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
        flows.append((tcp.sport, socket.inet_ntoa(ip.src), tcp.dport, socket.inet_ntoa(ip.dst)))
        cwnd_handler[tcp.sport] = [0]
        # cwnd_index[tcp.sport] = [0] # [ACK being tracked, index]
        trackThisPacket[tcp.sport] = [True, 0]
        port_rtt[tcp.sport] = ts
        
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
        # RTT = ACK - SYN ACK 
        port_rtt[tcp.sport] = ts - port_rtt[tcp.sport]

    # Checks if packet is first two and from sender
    if tcp.sport in transaction_handler and transaction_handler[tcp.sport][0] > 0:
        # Checks if packet has data in case piggy back
        if len(tcp.data) > 0:
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

    #Calculate congestion window
    # Check if ACK is sent by sender
    if tcp.flags & dpkt.tcp.TH_ACK and socket.inet_ntoa(ip.src) == senderIP:
        # dict[dict[arr[rtt of packet, # of packets sent (congestion window), continue, times retransmitted]]] => for every sequence number check rtt and packets sent
        if tcp.sport not in packet_ACK_handler and len(tcp.data) != 0:
            packet_ACK_handler[tcp.sport] = {}
            # Track retransmits and 3 Dup ACKs [retransmit, triple ACK]
            packet_retransmit[tcp.sport] = [0, 0]

        # Check if packets are already iterated through
        if tcp.sport in packet_ACK_handler and (len(tcp.data) + tcp.seq) in packet_ACK_handler[tcp.sport]:
            packet_retransmit[tcp.sport][0] += 1
        
        # Create new transactions for each packet
        if len(tcp.data) != 0 and (tcp.seq + len(tcp.data)) not in packet_ACK_handler[tcp.sport]:
            packet_ACK_handler[tcp.sport][tcp.seq + len(tcp.data)] = [ts, 0, True, -1, 0] #Receiver will send ACK with seq+len

    # Increment count for each packet sent after initial from sender
    # This idea was scrapped
    if tcp.flags & dpkt.tcp.TH_ACK and tcp.sport in packet_ACK_handler:
        for ackNum in list(packet_ACK_handler[tcp.sport].keys()):
            if packet_ACK_handler[tcp.sport][ackNum][2] == True:
                packet_ACK_handler[tcp.sport][ackNum][1] += 1

    # Get initial time of first packet in cwnd
    if tcp.sport in trackThisPacket and trackThisPacket[tcp.sport][0] and tcp.flags & dpkt.tcp.TH_ACK and len(tcp.data) != 0:
        initial_ts[tcp.sport] = ts
        trackThisPacket[tcp.sport][0] = False

    # Check if ts - first packet tracked > port_rtt[tcp.sport]
    if tcp.sport in initial_ts and tcp.flags & dpkt.tcp.TH_ACK and ts - initial_ts[tcp.sport] > port_rtt[tcp.sport]:
        trackThisPacket[tcp.sport][1] += 1
        trackThisPacket[tcp.sport][0] = True
        cwnd_handler[tcp.sport].append(0)

    if tcp.sport in cwnd_handler and tcp.flags & dpkt.tcp.TH_ACK and len(tcp.data) != 0:
        cwnd_handler[tcp.sport][trackThisPacket[tcp.sport][1]] += 1

    # Check for ACKs sent by Receiver
    # ACK# should be the seq#
    if tcp.flags & dpkt.tcp.TH_ACK and tcp.dport in packet_ACK_handler:
        # Get rtt of packet
        if tcp.ack in packet_ACK_handler[tcp.dport] and packet_ACK_handler[tcp.dport][tcp.ack][2] == True:
            rtt = ts - packet_ACK_handler[tcp.dport][tcp.ack][0]
            packet_ACK_handler[tcp.dport][tcp.ack][3] = rtt
            # packet_ACK_handler[tcp.dport][tcp.ack][1] += 1
            packet_ACK_handler[tcp.dport][tcp.ack][2] = False #Don't continue adding packets to counter

        if tcp.ack in packet_ACK_handler[tcp.dport]:
            packet_ACK_handler[tcp.dport][tcp.ack][4] += 1
            # Retransmitted 3 times
            if packet_ACK_handler[tcp.dport][tcp.ack][4] == 4:
                packet_retransmit[tcp.dport][1] += 1





print(f"Total Flows: {len(flows)}")
print()

for i in range(len(flows)):
    portNum = flows[i][0]
    print(f"Flow {i+1}")
    print(f"Part A:")
    print(f"Information (Sender Port, IP, Receiver Port, IP): {flows[i]}")
    print(f"Transaction 1: Seq#: {transactions.get(portNum)[0][0]} ACK: {transactions.get(portNum)[0][1]} Receive Window Size: {transactions.get(portNum)[0][2]}")
    print(f"Transaction 2: Seq#: {transactions.get(portNum)[1][0]} ACK: {transactions.get(portNum)[1][1]} Receive Window Size: {transactions.get(portNum)[1][2]}")
    print(f"Throughput: {timestamps[portNum][2]} Total Data: {timestamps[portNum][1]} Time Period: {timestamps[portNum][3]}")
    print(f"Part B:")
    i = 0
    for packets in cwnd_handler[portNum]:
        if i < 1:
            print(f"First 3 Congestion Window Sizes: ", end="")
        
        if i < 3:
            print(f"{packets} ", end="")

        i += 1
    print()
    print(f"Number of Total Retransmissions: {packet_retransmit[portNum][0]}")
    print(f"Number of Triple ACKs: {packet_retransmit[portNum][1]}")
    print(f"Number of Timeouts: {packet_retransmit[portNum][0] - packet_retransmit[portNum][1]}")
    print()
    
