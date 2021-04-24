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

    int retcode = pcap_loop(interface.get(), args->number, packet_handler, NULL);
    return 0;
}

void icmp_handler(const u_char *packet, unsigned int h_length, const struct pcap_pkthdr *h)
{
    cout << "ICMP\n";
    int t = *packet;
    cout << t << endl;
}

void udp_handler(const u_char *packet, unsigned int h_length, const struct pcap_pkthdr *h)
{
    cout << "UDP\n";
    const u_char *payload = skip_udp_header(packet);
    int payload_length = get_udp_length(const_cast<u_char *>(packet));
    print_payload(payload, payload_length);
}

void tcp_handler(const u_char *packet, unsigned int h_length, const struct pcap_pkthdr *h)
{
    cout << "TCP\n";
    unsigned int tcp_header_length = get_tcp_header_length(packet);
    const u_char *payload = packet + tcp_header_length;
    auto size = h->caplen - h_length - tcp_header_length;
    cout << size;
    print_payload(payload, size);
}

void ipv4_handler(const u_char *bytes, const struct pcap_pkthdr *h)
{
    printf("IPv4 ");
    const u_char *ip_header = skip_ether_header(bytes);
    int ip_protocol = get_ipv4_protocol(ip_header);
    int ip_header_length = get_ipv4_header_length(ip_header);
    const u_char *next_header = ip_header + ip_header_length;

    switch (ip_protocol)
    {
    case IPPROTO_ICMP:
    {
        icmp_handler(next_header, ETH_H_LEN + ip_header_length, h);
    }
    case IPPROTO_UDP:
    {
        udp_handler(next_header, ETH_H_LEN + ip_header_length, h);
    }
    case IPPROTO_TCP:
    {
        tcp_handler(next_header, ETH_H_LEN + ip_header_length, h);
    }

    default:
        break;
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{

    uint16_t ether_type = get_ether_type(bytes);

    if (ether_type == ETHERTYPE_IP)
    {
        ipv4_handler(bytes,h);
    }
    else if (ether_type == ETHERTYPE_IPV6)
    {
        cout << "IPv6 ";
        const u_char *ip = bytes + 14;
        u_char *n_header_p = const_cast<u_char *>(ip + 6);
        int n_header = *(n_header_p);

        bool end = false;

        do
        {
            switch (n_header)
            {
            case IPV6_TCP:
                cout << "TCP\n";
                end = true;
                break;
            case IPV6_UDP:
                cout << "UDP\n";
                end = true;
                break;
            case IPV6_ICMP:
                cout << "ICMP\n";
                end = true;
                break;
            case IPV6_NONEXT:
                cout << "Unknown\n";
                end = true;
                break;

            default:
                if (is_other_ext(n_header))
                {
                    n_header_p = (n_header_p + *(n_header_p + 1));
                    n_header = *n_header_p;
                }
                else
                {
                    end = true;
                }

                break;
            }

        } while (!end);
    }
    else if (ether_type == ETHERTYPE_ARP)
    {
        printf("ARP\n");
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
