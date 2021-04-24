#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H

#include "sniffer_classes.h"
#include <memory>

/**
 * @brief Stuff to happen with the captured packet
 * 
 * @param user No idea what is this
 * @param h Pcap packet header
 * @param bytes Contents of the packet
 */
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

/**
 * @brief Check if header found is extension header, that has another one behind.
 * 
 * @param header Current header
 * @return true If the header was recognized and you should expect next one
 * @return false Header was not recognized, probably is one of the upper layers header
 */
bool is_other_ext(int header);

/**
 * @brief Prints all avaliable network devices to stdin
 * 
 */
void print_devices();

std::unique_ptr<Arguments> parse_arguments(int argc, char *argv[]);


#endif // IPK_SNIFFER_H
