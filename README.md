UCLA CS118 Project (Simple Router)
====================================
Name: Zhenhua Tan
UID: 705185735

High level design of my implementation:

In the handlePacket()function of the simple-router.cpp file, I first parse the Ethernet header of the received packet.
Then I'll check its Ethernet type. If it's a ARP packet, I'll check if it's an ARP request or ARP reply. If it's an ARP request, I create an new packet and send ARP reply. If it's an ARP reply, I'll store the mapping of IP and MAC address into ARP cache. Then I'll send the cached packets out. However, if the Ethernet type is an IPv4, I'll first verify its checksum and length. Then I'll check who this packet is destined to. If it's for the router, I'll check if it's an ICMP packet. If so, I'll verify the ICMP checksum and then send the ICMP echo reply. Otherwise, I'll just discard the packet.
If the packet is not for the router, I'll update the TTL and checksum fields in the IP header of the packet. Then I'll
look up the routing table to find next hop address based on the destination IP in the IP header. When I get the next hop IP back from the routing table, I'll look up the ARP cache table based on this next hop IP, and get its MAC address.
If the entry is found, I'll create a new packet and forward it. However, if the entry is not found, I'll put it into a pending request queue, and send a ARP request asking for the MAC address. When the ARP reply arrives, I'll send out all the pending packets associated with this ARP request.

In the lookup() function of the routing-table.cpp file, I compare the given IP address against destination IP in all the entries in the given routing table. I fist convert all the IP addresses into binary, and strip the last n bits based on the mask. And then compare the given IP one by one against all the destination IP in the routing table. If a matching prefix is found, lookup() will return the next hop IP address associated with such prefix.

In the periodicCheckArpRequestsAndCacheEntries() of the arp-cache.cpp file, I also wrote two extras helper functions.
The first one is isValid() function, which is used as a predicate function when I try to remove all the stale ARP cache entries. The second one is handle_arpreq(), which will be called in periodicCheckArpRequestsAndCacheEntries(). This helper function is used to decide if a queued ARP request should be resent or removed.


Problems I ran into:

Initially, most of the problems I encountered are that I didn't know how to get the type of a header and cast a header.
Also, when I assigned a value to some fields of a header and later when I retrieved them, the value was not what I expected.

After that, I ran into problems that I had no clue at all how the router, the routing table and the ARP cache table are related, such as when should I look up the routing table and when to look up the ARP cache table.

During debugging, I encountered a problem that when the client pinged one of the router's interfaces, there was nothing show up on the client side.

How I solved the problems:

I read some of the code in utils.cpp file and found out how to get header type and cast to a certain header.
I used htons() and ntohs() when I wrote and read from any 16-bit fields in network header structures.

After asking some question on Piazza, I found out we should look up the routing table when we want to know which interface in the router a given packet should be forwarded. And then we look up the ARP cache table to get the MAC address of the target with the given destination IP address.

I fixed the bug by printing out the packet header and examining it. I found that the client's default gateway is router's sw3 interface while the destination IP of the packet is router's sw1 interface. However, I only checked if the destination IP is equal to the packet incoming interface IP, then I would conclude this packet is for the router. But in this case, the packet would not be considered for the router even though it was because I only compared the destination IP against the router interface where the packet was received. Finally, I used a for loop to compare the destination IP against all the router interfaces. And the bug was fixed.
