#ifndef PACKET_LIB_H
#define PACKET_LIB_H

#include <iostream>
#include <pcap.h>
#include <vector>
#include <net/ethernet.h>
#include <algorithm>
#include <math.h>

// protocol identifiers
#define IPV6_TCP 6
#define IPV6_UDP 17
#define IPV6_ICMP 58
#define IPV6_NONEXT 59

#define ETH_H_LEN 14

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



// ##################### INTERNET ######################
// ================== IPv4 ==================
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

// ================== ICMP ==================


// ##################### NETWORK ######################
// ================== UDP ==================
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
void print_payload(const u_char *payload, const unsigned int length);


/**
 * @brief Stuff to happen with the captured packet
 * 
 * @param user No idea what is this
 * @param h Pcap packet header
 * @param bytes Contents of the packet
 */
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

#endif // PACKET_LIB_H
