#include <net/ethernet.h>
#include <algorithm>
#include <math.h>
#include <pcap.h>
#include <iostream>
#include "packet_lib.h"


using std::cerr;
using std::cout;
using std::endl;


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

int get_ipv4_protocol(const u_char *ip_header)
{
    return *(ip_header + 9);
}

int get_ipv4_total_length(u_char *ip_header)
{
    uint16_t *len = reinterpret_cast<uint16_t*>(ip_header + 4);
    return (ntohs(*len))-8;
}

int get_ipv4_header_length(const u_char *ip_header)
{
    int ihl = (*ip_header) & 0x0F;
    return ihl * 4;
}

int get_udp_length(u_char *udp_header)
{
    uint16_t *len = reinterpret_cast<uint16_t*>(udp_header + 4);
    return (ntohs(*len))-8;
}

const u_char *skip_udp_header(const u_char *udp_header)
{
    return udp_header + 8;
}

void print_payload(const u_char *payload, const unsigned int length)
{
    u_char *tmp_ptr = const_cast<u_char *>(payload);
    for (int j = 0; j < ceil(static_cast<float>(length)/16); j++)
    {
        printf("0x%.4x: ", j*16);
        //hex print
        for (int i = 16*j; i < length; i++)
        {
            printf("%.2x", *(tmp_ptr + i));
            cout << " ";
        }

        cout << "  ";

        // ascii print
        for (int i = 16*j; i < length; i++)
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
        cout << endl;
    }
}

int get_tcp_header_length(const u_char *tcp_header){
    return ((*(tcp_header+12)) >> 4)*4;
}

