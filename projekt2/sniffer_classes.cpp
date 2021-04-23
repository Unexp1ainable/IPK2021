#include <string>
#include "sniffer_classes.h"

Arguments::Arguments(std::string interface_, bool tcp_, bool udp_, bool arp_, bool icmp_, unsigned int number, int port_): 
    interface{interface_}, tcp{tcp_}, udp{udp_}, arp{arp_}, icmp{icmp_}, number{number}, port{port_} {}

