#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

// Function to search for a keyword in packet payload and return the value
int search_for_keyword(const char *payload, const char *keyword, char *value, int value_size) {
    const char *found = strstr(payload, keyword);
    if (found != NULL) {
        sscanf(found, "%*[^:]: %s", value);
        return 1;
    }
    return 0;
}

void process_packet(const u_char *packet, int size) {
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    char *payload;

    // Extract IP and TCP headers
    ip_header = (struct ip *)(packet + 14); // Skip Ethernet header
    tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header

    // Check if the packet is TCP
    if (ip_header->ip_p == IPPROTO_TCP) {
        // Check if the source IP address matches the target
        if (ip_header->ip_src.s_addr == inet_addr("131.144.126.118")) {
            int src_port = ntohs(tcp_header->th_sport);
            int dst_port = ntohs(tcp_header->th_dport);
            int sum_of_ports = src_port + dst_port;

            // Task 4: Sum of connection ports
            printf("Sum of connection ports: %d\n", sum_of_ports);

            // Task 5: Search for milkshake flavor
            char milkshake_flavor[100];
            payload = (char *)(packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
            if (search_for_keyword(payload, "milkshake", milkshake_flavor, sizeof(milkshake_flavor))) {
                printf("Milkshake flavor: %s\n", milkshake_flavor);
            }
        }

        // Task 1: Search for the keyword "Flag"
        char flag_value[100];
        payload = (char *)(packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
        if (search_for_keyword(payload, "Flag", flag_value, sizeof(flag_value))) {
            printf("Flag found in packet: %s\n", flag_value);
        }
    }

    // Task 2: Check for the username "secret"
    char username_value[100];
    payload = (char *)(packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
    if (search_for_keyword(payload, "secret", username_value, sizeof(username_value))) {
        printf("Username 'secret' identified: %s\n", username_value);
    }

    // Task 3: Check TCP checksum and look for instructions
    if (tcp_header->th_sum == 0x0ac4) {
        printf("TCP checksum matched: 0x0ac4\n");
        char instructions_value[100];
        if (search_for_keyword(payload, "instructions", instructions_value, sizeof(instructions_value))) {
            printf("Instructions found in packet: %s\n", instructions_value);
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the .pcap file for reading
    handle = pcap_open_offline("your_file.pcap", errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // Loop through the packets in the file
    struct pcap_pkthdr header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL) {
        process_packet(packet, header.len);
    }

    // Close the pcap file
    pcap_close(handle);

    return 0;
}



