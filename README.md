Danny Li
CSE 310
Professor Jain
3/27/25

How to run code:
1. Have analysis_pcap_tcp.py and assignment2.pcap files in directory
2. In the terminal, enter or copy and paste: python3 analysis_pcap_tcp.py
3. Information will be displayed in the terminal

Notes:
    -   For this part, I generalized the way I came up with the solution. I categorized each data
        point by somehow relating it to the sender port or IP. I mostly used dictionaries to do this,
        so when I say we repeat this for every flow, we create new instances in the dictionaries when
        we encounter new sender ports.
    -   For more information on how I did some of the things I did, please look at my code, it should
        be somewhat well commented.

Part A:
    (a) There are 3 total flows in the pcap file. We can find this out by checking the number of SYN
        packets sent. Since only the sender sends packets with a SYN flag and without an ACK flag,
        we can determine that flow has been started. We store the flow's information (source port, destination IP, destination port, destinationIP) as a tuple in an array for all the flows.

    (b) To find the first two transactions, we first find the packet from the receiver with a SYN and ACK
        flag. Then we track only the first two transactions, with data in case there is piggy backing, after it. To find the receive window size we must find the window scaling factor, so in the packet with the SYN flag the sender sent, we find the window scaling factor in the tcp options. We iterate through the options until we get to the scaling factor, which we use to find the receive window size (). For the flow's first two transactions, we add the transaction's seq#, ACK, and receive window size as a tuple to a dictionary.

    (c) To find the throughput of a flow, first save the timestamp of the initial packet with the
        SYN flag. Then, for every tcp packet sent through by the sender, we add up the length of the packet. When we find the packet with the FIN flag, we check the next packet, which is the last ACK, and then take the difference in the timestamps and then finally compute the throughput.
        Divide the total length by the total time and we get the throughput. We repeat this for every flow.


Part B:
    (1) To find the first 3 congestion windows sizes, I have to track the number of packets sent during an RTT interval. To find the RTT of the packets in the flow, I found the time it took for the sender to send an ACK after it sends the initial SYN packet. This is the estimated RTT for the flow, which I used to calculate congestion window sizes. Afterwards, for every new cwnd, as long as the current timestamp - the timestamp of the first packet in the current congestion window is less than the RTT, we increment the number of packets we saw in this congestion window. If it's greater than the RTT, it means we've reached the end of the RTT interval and stop counting the packets sent. We then move on to the next cwnd and repeat the process, counting the number of packets sent in one RTT. We can see that the congestion window sizes grow as we continue through the flow.

    (2) To find the number of retransmissions, we simply check if the current packet has already been sent before by the sender. If the packet is in the dictionary that we use to track the packets sent to the receiver, we increment the retransmission count. To check for triple duplicate ACKs, we have to check the ACKs sent by the receiver. For every packet, we store the number of ACKs they get in a dictionary. When we check the ACKs sent by the receiver, we increment the counter for number of ACKs for the corresponding packet. If the counter reaches 4, meaning we have 3 duplicate ACKs, we increment the triple duplicate ACKs counter for the corresponding flow. Once the flow is iterated through, we subtract the total amount of retransmissions from the total amount of duplicate ACKs for the flow to find the total number of timeouts.



Program Output:

Total Flows: 3

Flow 1
Part A:
Information (Sender Port, IP, Receiver Port, IP): (43498, '130.245.145.12', 80, '128.208.2.198')
Transaction 1: Seq#: 705669103 ACK: 1921750144 Receive Window Size: 49152
Transaction 2: Seq#: 705669127 ACK: 1921750144 Receive Window Size: 49152
Throughput: 5133395.748425832 Total Data: 10320184 Time Period: 2.0104010105133057
Part B:
First 3 Congestion Window Sizes: 14 18 43 
Number of Total Retransmissions: 3
Number of Triple ACKs: 2
Number of Timeouts: 1

Flow 2
Part A:
Information (Sender Port, IP, Receiver Port, IP): (43500, '130.245.145.12', 80, '128.208.2.198')
Transaction 1: Seq#: 3636173852 ACK: 2335809728 Receive Window Size: 49152
Transaction 2: Seq#: 3636173876 ACK: 2335809728 Receive Window Size: 49152
Throughput: 1256538.3572691982 Total Data: 10454864 Time Period: 8.320369958877563
Part B:
First 3 Congestion Window Sizes: 10 22 33 
Number of Total Retransmissions: 94
Number of Triple ACKs: 30
Number of Timeouts: 64

Flow 3
Part A:
Information (Sender Port, IP, Receiver Port, IP): (43502, '130.245.145.12', 80, '128.208.2.198')
Transaction 1: Seq#: 2558634630 ACK: 3429921723 Receive Window Size: 49152
Transaction 2: Seq#: 2558634654 ACK: 3429921723 Receive Window Size: 49152
Throughput: 1448024.2286783182 Total Data: 1071936 Time Period: 0.7402749061584473
Part B:
First 3 Congestion Window Sizes: 20 43 63 
Number of Total Retransmissions: 0
Number of Triple ACKs: 0
Number of Timeouts: 0