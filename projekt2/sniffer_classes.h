#ifndef SNIFFER_CLASSES_H
#define SNIFFER_CLASSES_H

class Arguments
{
public:
    const std::string interface;
    const bool tcp;
    const bool udp;
    const bool arp;
    const bool icmp;
    const unsigned int number;
    const int port;

    Arguments(std::string interface_, bool tcp_, bool udp_, bool arp_, bool icmp_, unsigned int number, int port_);
};

#endif // SNIFFER_CLASSES_H
