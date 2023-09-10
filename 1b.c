#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

// Define a structure to represent a flow
typedef struct Flow {
    struct in_addr src_ip;
    struct in_addr dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
} Flow;

// Define a hash function for Flow struct
unsigned long hash_flow(const Flow* flow) {
    return ((unsigned long)flow->src_ip.s_addr << 16) | flow->src_port;
}

// Define equality check for Flow struct
int flow_equals(const Flow* flow1, const Flow* flow2) {
    return (flow1->src_ip.s_addr == flow2->src_ip.s_addr &&
            flow1->dest_ip.s_addr == flow2->dest_ip.s_addr &&
            flow1->src_port == flow2->src_port &&
            flow1->dest_port == flow2->dest_port);
}

void analyze_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    struct ip* ip_header = (struct ip*)(packet + 14); // Assuming Ethernet header is 14 bytes
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2)); // Assuming IPv4

    char source_ip_str[INET_ADDRSTRLEN];
    char dest_ip_str[INET_ADDRSTRLEN];

    // Convert source and destination IP addresses to strings
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip_str, INET_ADDRSTRLEN);

    printf("Source IP: %s\n", source_ip_str);
    printf("Destination IP: %s\n", dest_ip_str);

    // Perform reverse DNS lookup for source IP
    struct hostent* host_info = gethostbyaddr(&(ip_header->ip_src), sizeof(struct in_addr), AF_INET);
    if (host_info != NULL) {
        printf("Reverse DNS lookup for Source IP: %s -> %s\n", source_ip_str, host_info->h_name);
    }

    // Create a Flow object for the current packet
    Flow current_flow;
    memcpy(&current_flow.src_ip, &(ip_header->ip_src), sizeof(struct in_addr));
    memcpy(&current_flow.dest_ip, &(ip_header->ip_dst), sizeof(struct in_addr));
    current_flow.src_port = ntohs(tcp_header->th_sport);
    current_flow.dest_port = ntohs(tcp_header->th_dport);

    static Flow flows[10000];
    static int flow_count = 0;

    int flow_found = 0;
    for (int i = 0; i < flow_count; i++) {
        if (flow_equals(&current_flow, &flows[i])) {
            flow_found = 1;
            break;
        }
    }

    if (!flow_found) {
        // New flow found, add it to the list and increment the count
        if (flow_count < sizeof(flows) / sizeof(flows[0])) {
            memcpy(&flows[flow_count], &current_flow, sizeof(Flow));
            flow_count++;
            printf("New Flow Detected:\n");
            printf("Source IP: %s, Source Port: %d\n", source_ip_str, current_flow.src_port);
            printf("Destination IP: %s, Destination Port: %d\n", dest_ip_str, current_flow.dest_port);
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <path_to_pcap_file>\n", argv[0]);
        return 1;
    }

    char* filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file
    pcap_t* handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // Loop through packets and analyze them
    struct pcap_pkthdr header;
    const u_char* packet;

    int total_flows = 0;

    while ((packet = pcap_next(handle, &header)) != NULL) {
        analyze_packet(&header, packet);
        total_flows++;
    }

    pcap_close(handle);
    printf("Total Flows Observed: %d\n", total_flows);
    return 0;
}



