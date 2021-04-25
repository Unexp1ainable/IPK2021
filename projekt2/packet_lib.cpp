#include <net/ethernet.h>
#include <algorithm>
#include <math.h>
#include <sstream>
#include <pcap.h>
#include <time.h>
#include <charconv>
#include <iostream>
#include "packet_lib.h"

using std::cerr;
using std::cout;
using std::endl;

// ##################### DATA LINK ######################
// ================== ETHERNET ==================
uint16_t get_ether_type(const u_char *bytes)
{
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)bytes;

    return ntohs(eth_header->ether_type);
}

const u_char *skip_ether_header(const u_char *bytes)
{
    int ether_header_length = 14;
    return bytes + ether_header_length;
}
// ================== ARP ==================
void arp_handler(const u_char *bytes, const struct pcap_pkthdr *h)
{
    const u_char *arp_header = bytes + ETH_HLEN;
    char ipv4_src[INET_ADDRSTRLEN];
    char ipv4_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_header + 14, ipv4_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header + 24, ipv4_dst, INET_ADDRSTRLEN);

    char mac_add_src[MAC_ADD_LEN];
    get_mac_address(arp_header + 8, mac_add_src);

    uint16_t *op = reinterpret_cast<uint16_t *>(const_cast<u_char *>(arp_header) + 6);
    int operation = ntohs(*op);

    if (operation == 1)
    {
        cout << "ARP Request: Who has " << ipv4_dst << "? Tell " << ipv4_src << "\n";
    }
    else if (operation == 2)
    {
        cout << "ARP Reply: " << ipv4_src << " is at " << mac_add_src << "\n";
    }
}

// ##################### INTERNET ######################
// ================== IPv4 ==================
void ipv4_handler(const u_char *bytes, const struct pcap_pkthdr *h)
{
    printf("IPv4 ");
    const u_char *ip_header = skip_ether_header(bytes);
    int ip_protocol = get_ipv4_protocol(ip_header);
    int ip_header_length = get_ipv4_header_length(ip_header);
    const u_char *next_header = ip_header + ip_header_length;
    char src_ip[IPv4_ADDRESS_LEN];
    char dst_ip[IPv4_ADDRESS_LEN];
    get_ipv4(const_cast<u_char *>(ip_header), src_ip, dst_ip);

    switch (ip_protocol)
    {
    case IPPROTO_ICMP:
    {
        icmp_handler(next_header, ETH_HLEN + ip_header_length, h, src_ip, dst_ip);
        break;
    }
    case IPPROTO_UDP:
    {
        udp_handler(next_header, ETH_HLEN + ip_header_length, h, src_ip, dst_ip);
        break;
    }
    case IPPROTO_TCP:
    {
        tcp_handler(next_header, ETH_HLEN + ip_header_length, h, src_ip, dst_ip);
        break;
    }

    default:
        break;
    }
}

void get_ipv4(u_char *packet, char *src_ip, char *dst_ip)
{
    auto sip = std::string{};
    auto dip = std::string{};
    extract_ipv4(packet + 12, &sip);
    extract_ipv4(packet + 16, &dip);
    strncpy(src_ip, sip.c_str(), IPv4_ADDRESS_LEN);
    strncpy(dst_ip, dip.c_str(), IPv4_ADDRESS_LEN);
}

void extract_ipv4(u_char *where, std::string *ip)
{
    int n;
    for (int i = 0; i < 3; i++)
    {
        n = static_cast<int>(*where);
        ip->append(std::string(std::to_string(n)));
        ip->append(1, '.');
        where++;
    }
    n = static_cast<int>(*where);
    ip->append(std::string(std::to_string(n)));
}


int get_ipv4_protocol(const u_char *ip_header)
{
    return *(ip_header + 9);
}

int get_ipv4_total_length(u_char *ip_header)
{
    uint16_t *len = reinterpret_cast<uint16_t *>(ip_header + 4);
    return (ntohs(*len)) - 8;
}

int get_ipv4_header_length(const u_char *ip_header)
{
    int ihl = (*ip_header) & 0x0F;
    return ihl * 4;
}

// ================== IPv6 ==================
void ipv6_handler(const u_char *bytes, const struct pcap_pkthdr *h)
{
    cout << "IPv6 ";
    const u_char *ipv6_header = bytes + ETH_HLEN;
    int ipv6_hlen = 40;

    char ipv6_src[INET6_ADDRSTRLEN];
    char ipv6_dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ipv6_header + 8, ipv6_src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, ipv6_header + 24, ipv6_dst, INET6_ADDRSTRLEN);

    u_char *n_header_ptr = const_cast<u_char *>(ipv6_header + 6);
    int n_header_type = *(n_header_ptr);

    bool end = false;

    do
    {
        switch (n_header_type)
        {
        case IPV6_TCP:
            cout << "TCP\n";
            tcp_handler(ipv6_header + ipv6_hlen, ETH_HLEN + ipv6_hlen, h, ipv6_src, ipv6_dst);
            end = true;
            break;
        case IPV6_UDP:
            cout << "UDP\n";
            udp_handler(ipv6_header + ipv6_hlen, ETH_HLEN + ipv6_hlen, h, ipv6_src, ipv6_dst);
            end = true;
            break;
        case IPV6_ICMP:
            cout << "ICMP\n";
            icmp_handler(ipv6_header + ipv6_hlen, ETH_HLEN + ipv6_hlen, h, ipv6_src, ipv6_dst);
            end = true;
            break;
        case IPV6_NONEXT:
            cout << "Unknown\n";
            end = true;
            break;

        default:
            // check for extension headers
            if (is_other_ext(n_header_type))
            {
                int n_header_length = *(n_header_ptr + 1);
                n_header_ptr = (n_header_ptr + n_header_length);
                n_header_type = *n_header_ptr;
                ipv6_hlen += n_header_length;
            }
            else
            {
                end = true;
            }

            break;
        }

    } while (!end);
}

bool is_other_ext(int header)
{
    auto begin_iterator = IPV6_EXT_H_OTHERS.begin();
    auto end_iterator = IPV6_EXT_H_OTHERS.end();
    if (std::find(begin_iterator, end_iterator, header) != end_iterator)
    {
        return true;
    }
    return false;
}

// ================== ICMP ==================
void icmp_handler(const u_char *packet, unsigned int h_length, const struct pcap_pkthdr *h, char *src_ip, char *dst_ip)
{
    cout << "ICMP\n";
    // will print icmp header as data
    print_payload(packet, h->caplen - h_length, h, NO_PORT, NO_PORT, src_ip, dst_ip);
}


// ##################### NETWORK ######################
// ================== UDP ==================
void udp_handler(const u_char *packet, unsigned int h_length, const struct pcap_pkthdr *h, char *src_ip, char *dst_ip)
{
    cout << "UDP\n";
    const u_char *payload = skip_udp_header(packet);
    int payload_length = get_udp_length(const_cast<u_char *>(packet));

    int src_port;
    int dst_port;
    get_ports(const_cast<u_char *>(packet), &src_port, &dst_port);

    print_payload(payload, payload_length, h, src_port, dst_port, src_ip, dst_ip);
}

int get_udp_length(u_char *udp_header)
{
    uint16_t *len = reinterpret_cast<uint16_t *>(udp_header + 4);
    return (ntohs(*len)) - 8;
}

const u_char *skip_udp_header(const u_char *udp_header)
{
    return udp_header + 8;
}

// ================== TCP ==================
void tcp_handler(const u_char *packet, unsigned int h_length, const struct pcap_pkthdr *h, char *src_ip, char *dst_ip)
{
    cout << "TCP\n";
    unsigned int tcp_header_length = get_tcp_header_length(packet);
    const u_char *payload = packet + tcp_header_length;
    auto payload_length = h->caplen - h_length - tcp_header_length;

    int src_port;
    int dst_port;
    get_ports(const_cast<u_char *>(packet), &src_port, &dst_port);

    print_payload(payload, payload_length, h, src_port, dst_port, src_ip, dst_ip);
}

int get_tcp_header_length(const u_char *tcp_header)
{
    return ((*(tcp_header + 12)) >> 4) * 4;
}


// ########################### MISC ##################################
void print_payload(const u_char *payload, const unsigned int length, const struct pcap_pkthdr *h, int src_port, int dst_port, char *src_ip, char *dst_ip)
{
    u_char *tmp_ptr = const_cast<u_char *>(payload);

    struct tm *p_time = localtime(&(h->ts.tv_sec));
    char timeparttime[30];
    auto f_time = strftime(timeparttime, 30, "%Y-%m-%dT%H:%M:%S", p_time);
    char secondparttime[30];
    sprintf(secondparttime, ".%i+01:00", h->ts.tv_usec / 1000);

    if (src_port != NO_PORT)
        printf("%s%s %s : %i > %s : %i, length %i bytes\n", timeparttime, secondparttime, src_ip, src_port, dst_ip, dst_port, length);
    else
        printf("%s%s %s : > %s :, length %i bytes\n", timeparttime, secondparttime, src_ip, dst_ip, length);

    int lines = ceil(static_cast<float>(length) / 16);
    int chars = length;
    int linechars = 16;

    for (int j = 0; j < lines; j++)
    {
        if (chars >= 16)
            linechars = 16;
        else
            linechars = chars;

        // offset
        printf("0x%.4x: ", j * 16);

        // hex print
        for (int i = 16 * j; i < j * 16 + linechars; i++)
        {
            printf("%.2x", *(tmp_ptr + i));
            cout << " ";
        }

        cout << "  ";

        // ascii print
        for (int i = 16 * j; i < j * 16 + linechars; i++)
        {
            char to_print = *(tmp_ptr + i);

            if (isprint(to_print))
            {
                cout << *(tmp_ptr + i);
            }
            else
            {
                cout << ".";
            }
        }

        tmp_ptr += 16;
        chars -= 16;
        cout << endl;
    }
}


void get_ports(u_char *packet, int *src_port, int *dst_port)
{
    *src_port = ntohs(*reinterpret_cast<uint16_t *>(packet));
    *dst_port = ntohs(*reinterpret_cast<uint16_t *>(packet + 2));
}

void get_mac_address(const u_char *bytes, char *dest)
{
    sprintf(dest, "%x-%x-%x-%x-%x-%x", *bytes, *(bytes + 1), *(bytes + 2), *(bytes + 3), *(bytes + 4), *(bytes + 5));
}



