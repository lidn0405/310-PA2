Danny Li
CSE 310
Professor Jain
3/27/25

How to run code:
1. Have analysis_pcap_tcp.py and assignment2.pcap files in directory
2. In the terminal, enter or copy and paste: python3 analysis_pcap_tcp.py
3. Information will be displayed in the terminal

Part A:
    (a) There are 3 total flows in the pcap file. We can find this out by checking the number of SYN
        packets sent. Since only the sender sends packets with a SYN flag and without an ACK flag,
        we can determine that flow has been started. We can store the port and IP data in an array,
        which has a length of 3, which means there are 3 flows.

    (b)


Part B:




Program Output:

Flow 1 Information (Sender Port, IP, Receiver Port, IP): (43498, '130.245.145.12', 80, '128.208.2.198')
Transaction 1: Seq#: 705669103 ACK: 1921750144 Receive Window Size: 49152
Transaction 2: Seq#: 705669127 ACK: 1921750144 Receive Window Size: 49152
Throughput: 5133395.748425832 Total Data: 10320184 Time Period: 2.0104010105133057
RTT: 0.07277393341064453
First 3 Congestion Window Sizes: 10, 11, 12, 
Number of Total Retransmissions: 3
Number of Triple ACKs: 2
Number of Timeouts: 1

Flow 2 Information (Sender Port, IP, Receiver Port, IP): (43500, '130.245.145.12', 80, '128.208.2.198')
Transaction 1: Seq#: 3636173852 ACK: 2335809728 Receive Window Size: 49152
Transaction 2: Seq#: 3636173876 ACK: 2335809728 Receive Window Size: 49152
Throughput: 1256538.3572691982 Total Data: 10454864 Time Period: 8.320369958877563
RTT: 0.07310199737548828
First 3 Congestion Window Sizes: 10, 11, 10, 
Number of Total Retransmissions: 94
Number of Triple ACKs: 38
Number of Timeouts: 56

Flow 3 Information (Sender Port, IP, Receiver Port, IP): (43502, '130.245.145.12', 80, '128.208.2.198')
Transaction 1: Seq#: 2558634630 ACK: 3429921723 Receive Window Size: 49152
Transaction 2: Seq#: 2558634654 ACK: 3429921723 Receive Window Size: 49152
Throughput: 1448024.2286783182 Total Data: 1071936 Time Period: 0.7402749061584473
RTT: 0.0729210376739502
First 3 Congestion Window Sizes: 10, 11, 10, 
Number of Total Retransmissions: 0
Number of Triple ACKs: 0
Number of Timeouts: 0