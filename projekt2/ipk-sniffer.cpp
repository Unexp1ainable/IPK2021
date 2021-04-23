#include <iostream>
#include "ipk-sniffer.h"
#include <pcap.h>
#include <getopt.h>
#include <vector>
#include <sstream>

using std::cout;
using std::endl;

int main(int argc, char *argv[])
{
    auto args = parse_arguments(argc, argv);

    cout << args->interface << endl;
    cout << args->port << endl;

    delete args;
    return 0;
}

Arguments *parse_arguments(int argc, char *argv[])
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

    return new Arguments(interface, tcp, udp, arp, icmp, number, port);
}
