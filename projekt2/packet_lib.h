#ifndef PACKET_LIB_H
#define PACKET_LIB_H

#include <iostream>
#include <pcap.h>
#include <vector>
#include <net/ethernet.h>
#include <algorithm>
#include <math.h>
#include <string>
#include <string.h>

// protocol identifiers
#define IPV6_TCP 6
#define IPV6_UDP 17
#define IPV6_ICMP 58
#define IPV6_NONEXT 59


/**
 * @brief Possible codes of extension headers
 * 
 */
const std::vector<int> IPV6_EXT_H_OTHERS = {0, 43, 44, 50, 51, 60, 135};

// ##################### DATA LINK ######################
// ================== ETHERNET ==================
/**
 * @brief Get the EtherType
 * 
 * @param bytes Packet
 * @return uint16_t EtherType
 */
uint16_t get_ether_type(const u_char *bytes);

/**
 * @brief Skips ethernet header of packet
 * 
 * @param bytes Packet
 * @return const u_char* Pointer to the beginning of next header
 */
const u_char *skip_ether_header(const u_char *bytes);

// ================== ARP ==================
/**
 * @brief Handles ARP packet
 * 
 * @param bytes Pointer to the beginning of the packet
 * @param h Informations about the packet
 */
void arp_handler(const u_char *bytes, const struct pcap_pkthdr *h);

// ##################### INTERNET ######################
#define IPv4_ADDRESS_LEN 20
#define NO_PORT -1
// ================== IPv4 ==================
/**
 * @brief Handles IPv4 packets
 * 
 * @param bytes Packet data
 * @param h Informations about packet
 */
void ipv4_handler(const u_char *bytes, const struct pcap_pkthdr *h);

/**
 * @brief Get the ipv4 adresses from the ipv4 packet
 * 
 * @param packet Pointer to the beginning of the packet
 * @param src_ip Source IP address
 * @param dst_ip Destination IP address
 */
void get_ipv4(u_char *packet, char *src_ip, char *dst_ip);

/**
 * @brief Extracts IPv4 adress
 * 
 * @param where Pointer to the beginning of the adress
 * @param ip Pointer to the string where the result will be written
 */
void extract_ipv4(u_char *where, std::string *ip);

/**
 * @brief Get the next layer protocol
 * 
 * @param ip_header Pointer to the beginning of the IPv4 packet
 * @return int Protocol code
 */
int get_ipv4_protocol(const u_char *ip_header);

/**
 * @brief Extract total length from ipv4 packet
 * 
 * @param ip_header Pointer to the beginning of the IPv4 packet
 * @return int Size in bytes
 */
int get_ipv4_total_length(u_char *ip_header);

/**
 * @brief Get the length of ipv4 header
 * 
 * @param ip_header Pointer to the beginning of the IPv4 packet
 * @return int Length of the header in bytes
 */
int get_ipv4_header_length(const u_char *ip_header);

// ================== IPv6 ==================
/**
 * @brief Handles IPv6 packets
 * 
 * @param bytes Pointer to the beginning of the packet
 * @param h Informations about the packet
 */
void ipv6_handler(const u_char *bytes, const struct pcap_pkthdr *h);

/**
 * @brief Determine if there is other extension header behind current one
 * 
 * @param header Pointer to the header
 * @return true If there is one
 * @return false If there is not one
 */
bool is_other_ext(int header);

// ================== ICMP ==================
/**
 * @brief Handles ICMP packets
 * 
 * @param packet Pointer to the beginning of the packet
 * @param h_length Length of the combined lenghts of previous headers
 * @param h Informations about packet
 * @param src_ip Source ip address
 * @param dst_ip Destination ip address
 */
void icmp_handler(const u_char *packet, unsigned int h_length, const struct pcap_pkthdr *h, char *src_ip, char *dst_ip);

// ##################### NETWORK ######################
// ================== UDP ==================
/**
 * @brief Handles UDP packets
 * 
 * @param packet Pointer to the beginning of the UDP packet
 * @param h_length Length of the previous headers combined
 * @param h Packet informations
 * @param src_ip Source ip
 * @param dst_ip Destination ip
 */
void udp_handler(const u_char *packet, unsigned int h_length, const struct pcap_pkthdr *h, char *src_ip, char *dst_ip);
/**
 * @brief Get length of the UDP packet
 * 
 * @param udp_header Pointer to the beginning of the UDP packet
 * @return int Length of UDP packet in bytes
 */
int get_udp_length(u_char *udp_header);

/**
 * @brief Returns pointer to the payload of the UDP packet
 * 
 * @param udp_header Pointer to the beginning of the UDP packet
 * @return const u_char* Pointer to the payload
 */
const u_char *skip_udp_header(const u_char *udp_header);


// ================== TCP ==================
/**
 * @brief Handles TCP headers
 * 
 * @param packet Pointer to the beginning of the TCP packet
 * @param h_length Length of the previous headers combined
 * @param h Informations about packet
 * @param src_ip Source ip adress
 * @param dst_ip Destination ip address
 */
void tcp_handler(const u_char *packet, unsigned int h_length, const struct pcap_pkthdr *h, char *src_ip, char *dst_ip);

/**
 * @brief Get the tcp header length object
 * 
 * @param tcp_header 
 * @return int 
 */
int get_tcp_header_length(const u_char *tcp_header);


// ########################### MISC ##################################
/**
 * @brief Prints payload to the stdout in required format
 * 
 * @param payload Pointer to the beginning of the payload
 * @param length Length of the payload
 */
void print_payload(const u_char *payload, const unsigned int length, const struct pcap_pkthdr *h, int src_port, int dst_port, char *src_ip, char *dst_ip);


/**
 * @brief Extracts ports from the packet. Assuming ports are next to each other.
 * 
 * @param packet Pointer to the beginning of the ports
 * @param src_port Pointer where result source port will be written
 * @param dst_port Pointer where result destination port will be written
 */
void get_ports(u_char *packet, int *src_port, int *dst_port);

// minimum length of mac address string
#define MAC_ADD_LEN 19

/**
 * @brief Extracts mac address from the packet
 * 
 * @param bytes Pointer to the beginning of the mac adress
 * @param dest Pointer to the string where result will be written. Has to be at least MAC_ADD_LEN bytes long.
 */
void get_mac_address(const u_char *bytes, char *dest);

#endif // PACKET_LIB_H
