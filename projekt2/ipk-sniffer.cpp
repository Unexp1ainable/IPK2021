#include <iostream>
#include <pcap.h>
#include <getopt.h>
#include <vector>
#include <sstream>
#include <memory>
#include <net/ethernet.h>
#include <algorithm>
#include <iomanip>
#include <math.h>
#include "ipk-sniffer.h"

using std::cerr;
using std::cout;
using std::endl;

int main(int argc, char *argv[])
{
    auto args = parse_arguments(argc, argv);

    // initialise pcap
    char errbuff[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuff) == -1)
    {
        cerr << "Initialisation failed: \n";
        cerr << errbuff << "\n";
        return 1;
    }

    // check if -i was without parameter
    if (args->interface == "")
    {
        print_devices();
        return 0;
    }

    // TODO remove
    cout << "Interface: " << args->interface << endl;

    // open interface
    auto interface_unsafe = pcap_open_live(args->interface.c_str(), 1024, 1, 1000, errbuff);
    if (!interface_unsafe)
    {
        cerr << "Failed to open the descriptor.\n";
        return 1;
    }

    // declare custom deleter functor
    struct del_pcap_handle
    {
        del_pcap_handle(){};
        void operator()(pcap_t *handle)
        {
            pcap_close(handle);
        };
    };

    // transform it to unique ptr, so it is automatically closed at the end
    auto interface = std::unique_ptr<pcap_t, del_pcap_handle>(interface_unsafe, del_pcap_handle());

    std::string filter_str{};
    bool next = false;
    filter_str.append(std::string{"("});
    if (args->arp)
    {
        if (next)
            filter_str.append(std::string{" or"});
        else
            next = true;

        filter_str.append(std::string{" arp"});
    }
    if (args->icmp)
    {
        if (next)
            filter_str.append(std::string{" or"});
        else
            next = true;
        filter_str.append(std::string{" icmp"});
    }
    if (args->udp)
    {
        if (next)
            filter_str.append(std::string{" or"});
        else
            next = true;
        filter_str.append(std::string{" udp"});
    }
    if (args->tcp)
    {
        if (next)
            filter_str.append(std::string{" or"});
        else
            next = true;
        filter_str.append(std::string{" tcp"});
    }
    if (args->icmp)
    {
        if (next)
            filter_str.append(std::string{" or"});
        else
            next = true;
        filter_str.append(std::string{" icmp or icmp6"});
    }
    filter_str.append(std::string{")"});

    if (args->port != -1)
    {
        filter_str.append(std::string{" and port "});
        filter_str.append(std::to_string(args->port));
    }
    cout << filter_str << endl;

    struct bpf_program fp;
    if (pcap_compile(interface.get(), &fp, filter_str.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        cerr << "Failed to compile filter.\n";
        return 1;
    }

    if (pcap_setfilter(interface.get(), &fp) == -1)
    {
        cerr << "Failed to set filter.\n";
        return 1;
    }

    int retcode = pcap_loop(interface.get(), args->number, packet_handler, NULL);
    return 0;
}

void icmp_handler(const u_char *packet, unsigned int h_length, const struct pcap_pkthdr *h, char *src_ip, char *dst_ip)
{
    cout << "ICMP\n";
    // will print icmp header as data
    print_payload(packet, h->caplen - h_length, h, NO_PORT, NO_PORT, src_ip, dst_ip);
}

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

void get_mac_address(const u_char *bytes, char *dest)
{
    sprintf(dest, "%x-%x-%x-%x-%x-%x", *bytes, *(bytes + 1), *(bytes + 2), *(bytes + 3), *(bytes + 4), *(bytes + 5));
}

void arp_handler(const u_char *bytes, const struct pcap_pkthdr *h)
{
    int MAC_ADD_LEN = 19;
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

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{

    uint16_t ether_type = get_ether_type(bytes);

    if (ether_type == ETHERTYPE_IP)
    {
        ipv4_handler(bytes, h);
    }
    else if (ether_type == ETHERTYPE_IPV6)
    {
        ipv6_handler(bytes, h);
    }
    else if (ether_type == ETHERTYPE_ARP)
    {
        arp_handler(bytes, h);
    }
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

void print_devices()
{
    pcap_if_t *devices;
    char errbuff[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devices, errbuff) == -1)
    {
        cerr << "Failed to find devices.\n ";
    }

    cout << "Devices avaliable:\n";
    // print all devices
    for (pcap_if_t *temp = devices; temp; temp = temp->next)
    {
        cout << "\t" << temp->name << "\n";
    }
    pcap_freealldevs(devices);
}

/**
 * @brief Parse arguments
 * 
 * @param argc Number of arguments
 * @param argv Pointer to argument array
 * @return std::unique_ptr<Arguments> Instance of Arguments class filled with arguments.
 */
std::unique_ptr<Arguments> parse_arguments(int argc, char *argv[])
{
    enum option_identifiers
    {
        INTERFACE = 'i',
        TCP = 't',
        UDP = 'u',
        ARP = 'a',
        ICMP = 'c',
        NUMBER = 'n',
        PORT = 'p',
    };

    int arg;
    std::string interface{""};
    bool tcp = true;
    bool udp = true;
    bool arp = true;
    bool icmp = true;
    unsigned int number = 1;
    int port = -1;

    struct option longopts[] = {
        {"interface", optional_argument, nullptr, INTERFACE},
        {"tcp", no_argument, nullptr, TCP},
        {"udp", no_argument, nullptr, UDP},
        {"arp", no_argument, nullptr, ARP},
        {"icmp", no_argument, nullptr, ICMP},
        {nullptr, no_argument, nullptr, 0}};

    while ((arg = getopt_long(argc, argv, "i::p:tun:", longopts, nullptr)) != -1)
    {
        switch (arg)
        {
        case INTERFACE:
            if (argc > optind)
            {
                if (*argv[optind] != '-')
                {
                    interface = std::string{argv[optind]};
                    optind++;
                }
            }
            break;

        case TCP:
        {
            if (tcp)
            { // if other argument was already processed, tcp will be false. In that case, we do not want to set other to false
                udp = false;
                icmp = false;
                arp = false;
            }
            else
            {
                tcp = true;
            }
            break;
        }

        case UDP:
        {
            if (udp)
            { // if other argument was already processed, udp will be false. In that case, we do not want to set other to false
                tcp = false;
                icmp = false;
                arp = false;
            }
            else
            {
                udp = true;
            }
            break;
        }

        case ARP:
        {
            if (arp)
            { // if other argument was already processed, arp will be false. In that case, we do not want to set other to false
                udp = false;
                tcp = false;
                icmp = false;
            }
            else
            {
                arp = true;
            }
            break;
        }

        case ICMP:
        {
            if (icmp)
            { // if other argument was already processed, icmp will be false. In that case, we do not want to set other to false
                udp = false;
                tcp = false;
                arp = false;
            }
            else
            {
                icmp = true;
            }
            break;
        }

        case NUMBER:
        {
            std::stringstream ss(optarg);
            if (!(ss >> number))
                throw std::bad_cast{};
            break;
        }

        case PORT:
        {
            std::stringstream ss2(optarg);

            if (!(ss2 >> port))
                throw std::bad_cast{};
            break;
        }

        default:
        {
            cout << "ERROR" << arg << endl;
            throw std::invalid_argument{"Invalid argument."};
            break;
        }
        }
    }

    return std::make_unique<Arguments>(interface, tcp, udp, arp, icmp, number, port);
}
