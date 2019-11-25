/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

//Buffer = std:vector<unsigned char>
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  //for testing
  //std::cout << m_arp << std::endl;
  //std::cerr << getRoutingTable() << std::endl;

  //break down packet
  //print_hdrs(packet);

  //print out the mac address and ip adress of all
  //the interfaces in the router
  printIfaces(std::cout);

  // If interface is known, read ethernet header and check eth_type field
  // ignore all but ARP and IPv4 types
  const uint8_t* buf = packet.data();
  ethernet_hdr *ehdr = (ethernet_hdr *)buf;
  uint16_t type = ntohs(ehdr->ether_type);
  //print_hdr_eth(buf);

  //IPV4 type, act accordingly
  if(type == ethertype_ip) {
    std::cout << "IPV4 type" << std::endl;
    const uint8_t* ibuf = buf + sizeof(ethernet_hdr);
    ip_hdr *ihdr = (ip_hdr *)ibuf;

    //verify checksum
    uint16_t ip_sum = ihdr->ip_sum;
    ihdr->ip_sum = 0;
    if (cksum(ihdr, sizeof(ip_hdr)) != ip_sum) {
      std::cout << "IP header checksum fails!" << std::endl;
      return;
    }

    //reset to original ip_sum
    ihdr->ip_sum = ip_sum;

    if (ntohs(ihdr->ip_len) < sizeof(ip_hdr) + sizeof(ethernet_hdr)) {
      std::cout << "IP header length cannot be smaller than 34 bytes." << std::endl;
      return;
    }

    //check if destination IP is for the router
    //by comparing dest IP against all the interfaces
    bool forRouter = false;
    for(auto const& in : m_ifaces) {
      if(ipToString(ihdr->ip_dst) == ipToString(in.ip)) {
        forRouter = true;
        break;
      }
    }

    if(forRouter) {
      //Is it ICMP packet?
      uint8_t ip_proto = ip_protocol(buf + sizeof(ethernet_hdr));
      if (ip_proto == ip_protocol_icmp) {
        const uint8_t* icmpbuf = buf + sizeof(ethernet_hdr) + sizeof(ip_hdr);
        icmp_hdr *icmphdr = (icmp_hdr *)icmpbuf;

        //verify ICMP checksum
        uint16_t icmp_sum = icmphdr->icmp_sum;
        icmphdr->icmp_sum = 0;

        //checksum icmp header and the data following it
        int size = packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr);
        if (cksum(icmphdr, size) != icmp_sum) {
          std::cout << "ICMP header checksum fails!" << std::endl;
          return;
        }

        icmphdr->icmp_sum = icmp_sum;

        //echo message
        if((int)icmphdr->icmp_type == 8) {
          std::cout << "echo message!" << std::endl;

          //now prepare to reply
          //Buffer response(sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr));
          Buffer response(packet.size());
          const uint8_t* rbuf = response.data();

          //build ethernet header
          ethernet_hdr *re_hdr = (ethernet_hdr *)rbuf;
          std::copy(std::begin(ehdr->ether_shost), std::end(ehdr->ether_shost), std::begin(re_hdr->ether_dhost));
          std::copy(std::begin(iface->addr), std::end(iface->addr), std::begin(re_hdr->ether_shost));
          re_hdr->ether_type = htons((uint16_t)ethertype_ip);

          //build IP header
          const uint8_t* ribuf =rbuf + sizeof(ethernet_hdr);
          ip_hdr *ri_hdr = (ip_hdr *)ribuf;

          ri_hdr->ip_hl = ihdr->ip_hl;
          ri_hdr->ip_v = ihdr->ip_v;
          ri_hdr->ip_tos = ihdr->ip_tos;
          ri_hdr->ip_len = ihdr->ip_len;
          ri_hdr->ip_id = ihdr->ip_id;
          ri_hdr->ip_off = ihdr->ip_off;
          ri_hdr->ip_ttl = ihdr->ip_ttl;
          ri_hdr->ip_p = ihdr->ip_p;
          ri_hdr->ip_src = iface->ip;
          ri_hdr->ip_dst = ihdr->ip_src;
          ri_hdr->ip_sum = 0;
          ri_hdr->ip_sum = cksum(ri_hdr, sizeof(ip_hdr));

          //build ICMP header
          const uint8_t* ricmpbuf = ribuf + sizeof(ip_hdr);
          icmp_hdr *ricmphdr = (icmp_hdr *)ricmpbuf;
          ricmphdr->icmp_type = 0;
          ricmphdr->icmp_code = 0;
          ricmphdr->icmp_sum = 0;
          ricmphdr->icmp_sum = cksum(ricmphdr, sizeof(icmp_hdr));

          //build ICMP data
          const uint8_t* buff = icmpbuf + sizeof(icmp_hdr);
          //size = data_size + sizeof(icmp_hdr)
          Buffer data(buff, buff + size - sizeof(icmp_hdr));

          uint8_t* data_buf = response.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr);
          std::copy(std::begin(data), std::end(data), data_buf);

          //print_hdr_eth(rbuf);
          //print_hdr_ip(ribuf);
          //send ICMP echo reply
          sendPacket(response, iface->name);
        }

        //echo reply message, discard
        else if ((int)icmphdr->icmp_type == 0) {
          return;
        }
      }

      //destined to the router, but not an ICMP packet, discard
      else
        return;
    }

    //if packet is not for the router, forward the packet
    else {
      //update IP header (TTL and checksum)
      ihdr->ip_ttl -= 1;
      ihdr->ip_sum = 0;
      ihdr->ip_sum = cksum(ihdr, sizeof(ip_hdr));

      //std::cout << "srouce: " << ipToString(ihdr->ip_src) << std::endl;
      //std::cout << "destination: " << ipToString(ihdr->ip_dst) << std::endl;
      //std::cout << "interface: " << iface->name << std::endl;

      //lookup table entry, find the next-hop IP associated with
      //the router out interface and forward it
      RoutingTableEntry RTE = m_routingTable.lookup(ihdr->ip_dst);
      const Interface* out_face = findIfaceByName(RTE.ifName);

      //std::cout << "out face: " << out_face->name << std::endl;

      //modify destination MAC address in ethernet header
      //but first need to lookup the ARP cache table for the MAC address
      //if found, forward it, if not, send ARP request
      std::shared_ptr<ArpEntry> ARP_entry = m_arp.lookup(ihdr->ip_dst);

      //if ARP entry found, forward the packet
      if(ARP_entry != nullptr) {
        std::cout << "ip forward!" << std::endl;
        /*
        Buffer forward_packet = packet;
        const uint8_t* fbuf = forward_packet.data();
        ethernet_hdr *efhdr = (ethernet_hdr *)fbuf;
        std::copy(std::begin(ARP_entry->mac), std::end(ARP_entry->mac), std::begin(efhdr->ether_dhost));
        std::copy(std::begin(out_face->addr), std::end(out_face->addr), std::begin(efhdr->ether_shost));
        print_hdrs(forward_packet);
        */

        const uint8_t* fbuf = packet.data();
        ethernet_hdr *efhdr = (ethernet_hdr *)fbuf;
        std::copy(std::begin(ARP_entry->mac), std::end(ARP_entry->mac), std::begin(efhdr->ether_dhost));
        std::copy(std::begin(out_face->addr), std::end(out_face->addr), std::begin(efhdr->ether_shost));
        //print_hdrs(packet);
        sendPacket(packet, out_face->name);

        //sendPacket(forward_packet, out_face->name);
      }
      //if not, cache the packet and send ARP request
      else {
        std::cout << "no cache, ARP request!" << std::endl;
        std::shared_ptr<ArpRequest> ARP_request = m_arp.queueRequest(ihdr->ip_dst, packet, out_face->name);

        //send ARP request for the MAC addression associated with destination IP
        Buffer mac_request(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        const uint8_t* mac_buf = mac_request.data();

        //build ethernet header
        ethernet_hdr *emac_hdr = (ethernet_hdr *)mac_buf;
        std::copy(std::begin(out_face->addr), std::end(out_face->addr), std::begin(emac_hdr->ether_shost));

        //initialize broadcast MAC address
        for(int i = 0; i < ETHER_ADDR_LEN; i++) {
          emac_hdr->ether_dhost[i] = 255;
        }

        emac_hdr->ether_type = htons((uint16_t)ethertype_arp);

        //build ARP header
        const uint8_t* ARP_MAC_buf = mac_buf + sizeof(ethernet_hdr);
        arp_hdr *ARP_MAC_hdr = (arp_hdr *)ARP_MAC_buf;
        ARP_MAC_hdr->arp_hrd = htons(1);
        ARP_MAC_hdr->arp_pro = htons(ethertype_ip);
        ARP_MAC_hdr->arp_hln = (char)ETHER_ADDR_LEN;
        ARP_MAC_hdr->arp_pln = (char)4;
        ARP_MAC_hdr->arp_op = htons(1); //ARP request
        ARP_MAC_hdr->arp_sip = out_face->ip;
        ARP_MAC_hdr->arp_tip = ihdr->ip_dst;
        std::copy(std::begin(out_face->addr), std::end(out_face->addr), std::begin(ARP_MAC_hdr->arp_sha));

        //initialize target MAC address to all 0's
        for(int i = 0; i < ETHER_ADDR_LEN; i++) {
          ARP_MAC_hdr->arp_tha[i] = 0;
        }

        //broadcast
        //print_hdrs(mac_request);
        sendPacket(mac_request, out_face->name);
      }
    }


  }

  //ARP type, act accordingly
  else if(type == ethertype_arp) {
    std::cout << "ARP type" << std::endl;
    const uint8_t* abuf = buf + sizeof(ethernet_hdr);
    arp_hdr *ahdr = (arp_hdr *)abuf;

    //ARP request
    if(ntohs(ahdr->arp_op) == 1) {
      std::cout << "arp request!" << std::endl;
      // if the ARP target IP address is one of the router interface's, (its' for the router)
      // then fill in the corresponding interface mac address in the ARP packet
      if(ahdr->arp_tip == iface->ip) {
        for(int i =0 ; i< 6; i++) {
          ahdr->arp_tha[i] = iface->addr[i];
        }

        //now prepare to reply
        Buffer response(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        const uint8_t* rbuf = response.data();

        //build ethernet header
        ethernet_hdr *re_hdr = (ethernet_hdr *)rbuf;
        std::copy(std::begin(ehdr->ether_shost), std::end(ehdr->ether_shost), std::begin(re_hdr->ether_dhost));
        std::copy(std::begin(iface->addr), std::end(iface->addr), std::begin(re_hdr->ether_shost));
        re_hdr->ether_type = htons((uint16_t)ethertype_arp);

        //build ARP header
        const uint8_t* rabuf =rbuf + sizeof(ethernet_hdr);
        arp_hdr *ra_hdr = (arp_hdr *)rabuf;
        ra_hdr->arp_hrd = ahdr->arp_hrd;
        ra_hdr->arp_pro = ahdr->arp_pro;
        ra_hdr->arp_hln = ahdr->arp_hln;
        ra_hdr->arp_pln = ahdr->arp_pln;
        ra_hdr->arp_op = htons(2); //ARP reply
        ra_hdr->arp_sip = iface->ip;
        ra_hdr->arp_tip = ahdr->arp_sip;
        std::copy(std::begin(iface->addr), std::end(iface->addr), std::begin(ra_hdr->arp_sha));
        std::copy(std::begin(ahdr->arp_sha), std::end(ahdr->arp_sha), std::begin(ra_hdr->arp_tha));


        //print_hdrs(response);
        //send response
        sendPacket(response, iface->name);
      }
    }

    //ARP reply
    else if (ntohs(ahdr->arp_op) == 2) {
      std::cout << "arp reply" << std:: endl;
      //store IP/MAC info and then send cached packets out
      Buffer mac(ETHER_ADDR_LEN);
      std::copy(std::begin(ahdr->arp_sha), std::end(ahdr->arp_sha), std::begin(mac));
      std::shared_ptr<ArpRequest> req = m_arp.insertArpEntry(mac, ahdr->arp_sip);

      //print_hdr_arp(abuf);
      //if the request packet associated with this IP address found
      if(req != nullptr) {
        //forward all the packets that want to go there
        for(auto const& p_req : req->packets) {
          const uint8_t* req_buf = p_req.packet.data();
          ethernet_hdr *ether_req_hdr = (ethernet_hdr *)req_buf;
          const uint8_t* ip_req_buf = req_buf + sizeof(ethernet_hdr);
          ip_hdr * ip_req_hdr = (ip_hdr *)ip_req_buf;

          //update ip header
          //ip_req_hdr->ip_ttl -= 1;
          ip_req_hdr->ip_sum = 0;
          ip_req_hdr->ip_sum = cksum(ip_req_hdr, sizeof(ip_hdr));

          //update ethernet header Dest and Src Addr
          std::copy(std::begin(ahdr->arp_sha), std::end(ahdr->arp_sha), std::begin(ether_req_hdr->ether_dhost));
          std::copy(std::begin(ahdr->arp_tha), std::end(ahdr->arp_tha), std::begin(ether_req_hdr->ether_shost));

          //print_hdrs(p_req.packet);
          sendPacket(p_req.packet, p_req.iface);
        }
        //remove the request from the queue
        m_arp.removeRequest(req);
      }
    }
  }
  //unknown type
  else {
    std::cout << "Incomging packet must be IPV6." << std::endl;
    return;
  }

  std::cout << std::endl;
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
