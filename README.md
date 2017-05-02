The goal of this project is to take a URL on the command line and downloads the associated file. 
We implemented protocol stacks from Data-link Layer to Application Layer, including building 
the Ethernet, IP and TCP headers in each packet. We learned some code and protocol format 
arguments from Wikipedia, Python Official Documentation and some technical blogs.

Implementation of Each Layer:
We implement the protocol stack as below:
--------------------------------------------------------------------------
|                 |           |                    |           |         |
| Ethernet Header | IP Header |     TCP Header     | HTTP Data | Padding |
|                 |           |                    |           |         |
--------------------------------------------------------------------------
|     14 byte     |  20 byte  |   20 byte or more  |           |add to 64|
--------------------------------------------------------------------------
---
Data-link Layer:
We used AF_PACKET raw socket, which bypasses the operating systems layer-2 stack. So we implemented
Ethernet Frame by ourselves. The Ehternet Frame could be used for packing IP datagram and ARP
packet. 

At first, we used ARP boardcast to query the destination hardware address, in particular it will be
gateway MAC address. To achieve this, we get gateway IP address from route table, then
we set Ethernet Frame THA (Target Hardware Address) to the broadcast address:"FF:FF:FF:FF:FF:FF" 
to send the ARP request to each host in LAN until we get the respond ARP packet from gateway 
with its MAC address.

After that, we have SHA, THA, SPA, TPA and every other things we need. We packed the IP Datagram into
Ethernet Frame as the data field. And then we implemented Ethernet Socket to send and receive the 
Ethernet Frame with the full IP Datagram as its data, because the minimum frame size is 64 byte,
if the frame is shorter than it, Ethernet Frame will add some "0000" as padding at the end until
reach 64 byte.


Network Layer:
The implementation of IP Datagram is basically the same as IPv4, including Src IP Address, 
Dest IP Address, Version, Length, Flag, Fragment Offset, TTL and Checksum. 

The checksum is calculated by forming the ones' complement of the ones' complement sum of the header's 
16-bit words. The result of summing entire IP header, including checksum, should be zero if there is 
no corruption. At each hop, the checksum is recalculated and the packet will be discarded upon 
checksum mismatch.

After the calculation of Checksum, we place the result in the Checksum field of the sending packet.
And we implement a IP socket to send and receive the IP datagram, which contains the TCP packet as
its data field.


Transport Layer:
In this layer, we implemented the TCP protocol, with functionality like Checksum, Congestion
Window and advertised Window.