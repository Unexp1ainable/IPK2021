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

    std::unique_ptr<Arguments> args;
    try
    {
        args = parse_arguments(argc, argv);
    }
    catch(const std::bad_cast& e)
    {
        std::cerr << "Invalid numeric value." << '\n';
        return 1;
    }
    catch(const std::invalid_argument& e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }
    
    

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

    // create filter
    std::string filter_str{};
    assemble_filter_str(&filter_str, args.get());

    struct bpf_program fp;
    if (pcap_compile(interface.get(), &fp, filter_str.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        cerr << "Failed to compile filter.\n";
        return 1;
    }

    // set filter
    if (pcap_setfilter(interface.get(), &fp) == -1)
    {
        cerr << "Failed to set filter.\n";
        return 1;
    }

    // capture packets
    int retcode = pcap_loop(interface.get(), args->number, packet_handler, NULL);
    return 0;
}

void assemble_filter_str(std::string *filter_str, Arguments *args)
{
    bool next = false;
    filter_str->append(std::string{"("});
    if (args->arp)
    {
        if (next)
            filter_str->append(std::string{" or"});
        else
            next = true;

        filter_str->append(std::string{" arp"});
    }
    if (args->icmp)
    {
        if (next)
            filter_str->append(std::string{" or"});
        else
            next = true;
        filter_str->append(std::string{" icmp"});
    }
    if (args->udp)
    {
        if (next)
            filter_str->append(std::string{" or"});
        else
            next = true;
        filter_str->append(std::string{" udp"});
    }
    if (args->tcp)
    {
        if (next)
            filter_str->append(std::string{" or"});
        else
            next = true;
        filter_str->append(std::string{" tcp"});
    }
    if (args->icmp)
    {
        if (next)
            filter_str->append(std::string{" or"});
        else
            next = true;
        filter_str->append(std::string{" icmp or icmp6"});
    }
    filter_str->append(std::string{")"});

    if (args->port != -1)
    {
        filter_str->append(std::string{" and port "});
        filter_str->append(std::to_string(args->port));
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
            throw std::invalid_argument{"Invalid argument."};
            break;
        }
        }
    }

    return std::make_unique<Arguments>(interface, tcp, udp, arp, icmp, number, port);
}
