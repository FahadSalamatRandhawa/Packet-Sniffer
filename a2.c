#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <stdlib.h>

// Function declaration
void print_packet_data(const unsigned char *packet, int length);

void process_ipv4_header(struct ip *ip_header) {
    // Display IPv4 header information
    printf("Source IP (IPv4): %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP (IPv4): %s\n", inet_ntoa(ip_header->ip_dst));
}

void process_ipv6_header(struct ip6_hdr *ipv6_header) {
    // Display IPv6 header information
    char source_ip[INET6_ADDRSTRLEN];
    char dest_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), source_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dest_ip, INET6_ADDRSTRLEN);

    printf("Source IP (IPv6): %s\n", source_ip);
    printf("Destination IP (IPv6): %s\n", dest_ip);
}

void process_tcp_header(struct tcphdr *tcp_header) {
    // Display TCP header information
    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
}

// Function declaration
void print_packet_data(const unsigned char *packet, int length) {
    printf("Packet Data:\n");
    for (int i = 0; i < length; i++) {
        printf("%02X ", packet[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip_header;
    struct ip6_hdr *ipv6_header;
    struct tcphdr *tcp_header;

    // Parse Ethernet header
    unsigned short ethernet_type = (packet[12] << 8) | packet[13];

    if (ethernet_type == 0x0800) { // IPv4
        ip_header = (struct ip *)(packet + 14);
        process_ipv4_header(ip_header);

        // Check if the packet contains a TCP header
        if (ip_header->ip_p == IPPROTO_TCP) {
            tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2));
            process_tcp_header(tcp_header);
        }
    } else if (ethernet_type == 0x86DD) { // IPv6
        ipv6_header = (struct ip6_hdr *)(packet + 14);
        process_ipv6_header(ipv6_header);

        // Additional logic for IPv6 headers or extension headers if needed

        // Example: Check if the packet contains a TCP header
        if (ipv6_header->ip6_nxt == IPPROTO_TCP) {
            // Adjust the offset based on IPv6 header size
            tcp_header = (struct tcphdr *)(packet + 14 + sizeof(struct ip6_hdr));
            process_tcp_header(tcp_header);
        }
    }

    // Print the raw bytes of the packet
    print_packet_data(packet, pkthdr->len);
    printf("\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Find a suitable network device using pcap_findalldevs
    pcap_if_t *dev_list;
    if (pcap_findalldevs(&dev_list, errbuf) == -1) {
        fprintf(stderr, "Error finding network devices: %s\n", errbuf);
        return 1;
    }

    // Use the first device from the list
    char *dev = dev_list->name;
    printf("Using device: %s\n", dev);

    // Open the network device for packet capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return 1;
    }

    // Start capturing packets
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "Error in pcap_loop: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // Close the capture handle
    pcap_close(handle);

    // Free the device list
    pcap_freealldevs(dev_list);

    return 0;
}

