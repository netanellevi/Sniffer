#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define USAGE_MSG "This Program is printing packets in layer specified as argument.\n"\
            "Usage: Sniffer <Layer> where Layer is either 2(Link) or 3(Network) or 4(Transport)\n"\
            "If no layer specified it will print all layers.\n"\
            "Use Ctrl+C to stop the program. You need to run this program in sudo mode\n "

#define PACKET_SIZE 50000

enum Layer {
    ALL = 0, Link = 2, Network, Transport
};

enum TransportProtocol {
    ICMP = 1, TCP = 6, UDP = 17
};

unsigned char *packetBuf;

void gracefulExit(int status) {
    printf("Exiting...\n");
    free(packetBuf);
    exit(status);
}

void printPayload(unsigned char *buf, unsigned char size, unsigned char headerSize);

unsigned char printLinkHeader(unsigned char *buf) {
    struct ethhdr *ethhdr = (struct ethhdr *) (buf);
    printf("Source Mac: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
           ethhdr->h_source[0], ethhdr->h_source[1], ethhdr->h_source[2],
           ethhdr->h_source[3], ethhdr->h_source[4], ethhdr->h_source[5]);
    printf("Destination Mac: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
           ethhdr->h_dest[0], ethhdr->h_dest[1], ethhdr->h_dest[2],
           ethhdr->h_dest[3], ethhdr->h_dest[4], ethhdr->h_dest[5]);
    printf("Protocol %u\n", ethhdr->h_proto);
    return sizeof(struct ethhdr);
}

unsigned char printNetworkHeader(unsigned char *buf) {
    struct iphdr *iphdr = (struct iphdr *) (buf + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));
    source.sin_addr.s_addr = iphdr->saddr;
    dest.sin_addr.s_addr = iphdr->daddr;
    printf("Source IP: %s\n", inet_ntoa(source.sin_addr));
    printf("Dest IP: %s\n", inet_ntoa(dest.sin_addr));
    return sizeof(struct ethhdr) + sizeof(struct iphdr);
}

unsigned char printTransportHeader(unsigned char *buf) {
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    struct icmphdr *icmphdr;
    void *prevLayersEnd;

    struct iphdr *iphdr = (struct iphdr *) (buf + sizeof(struct ethhdr));
    unsigned short iphdr_len = (unsigned short) (iphdr->ihl) * 4;
    prevLayersEnd = buf + iphdr_len + sizeof(struct ethhdr);
    unsigned char headerSize = sizeof(struct ethhdr) + iphdr_len;
    switch (iphdr->protocol) {
        case TCP:
            tcphdr = (struct tcphdr *) prevLayersEnd;
            headerSize += tcphdr->doff * 4;
            printf("TCP Packet:\n");
            printf("Source Port: %u\n", ntohs(tcphdr->source));
            printf("Destination Port: %u\n", ntohs(tcphdr->dest));
            printf("Sequence number: %u\n", ntohs(tcphdr->seq));
            printf("Acknowledge sequence number: %u\n", ntohs(tcphdr->ack_seq));
            printf("Checksum: %d\n", ntohs(tcphdr->check));
            break;
        case UDP:
            udphdr = (struct udphdr *) prevLayersEnd;
            headerSize += sizeof(udphdr);
            printf("UCP Packet:\n");
            printf("Source Port: %d\n", ntohs(udphdr->source));
            printf("Destination Port: %d\n", ntohs(udphdr->dest));
            printf("UDP length: %d\n", ntohs(udphdr->len));
            printf("Checksum: %d\n", ntohs(udphdr->check));
            break;
        case ICMP:
            icmphdr = (struct icmphdr *) prevLayersEnd;
            headerSize += sizeof(icmphdr);
            printf("ICMP Packet:\n");
            printf("Type %d\n", (unsigned int) icmphdr->type);
            printf("Code %d\n", (unsigned int) icmphdr->code);
            printf("Checksum %d\n", ntohs(icmphdr->checksum));
            break;
        default:
            printf("Other protocol packet:\n");
    }
    return headerSize;
}

void printPayload(unsigned char *buf, unsigned char size, unsigned char headerSize) {
    printf("Payload:\n");
    for (unsigned char i = headerSize; i < size; ++i) {
        if (i % 16 == 0) printf("\n");
        printf("%.2X ", buf[i]);
    }
    printf("\n\n");
}

unsigned char printAllLayers(unsigned char *buf) {
    printLinkHeader(buf);
    printNetworkHeader(buf);
    return printTransportHeader(buf);
}

void printPackets(enum Layer layer) {
    unsigned char (*printPacketHeaders)(unsigned char *);
    struct sockaddr s_addr;
    int s_addr_size = sizeof(s_addr), dataSize;
    packetBuf = (unsigned char *) malloc(sizeof(unsigned char) * PACKET_SIZE);
    if (packetBuf == NULL) gracefulExit(EXIT_FAILURE);
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket Error.\nTry to use sudo to run this program\n");
        gracefulExit(EXIT_FAILURE);
    }
    if (layer == ALL) printf("Printing Packets in all layers\n\n");
    else printf("Printing Packets in layer %d\n\n", layer);
    unsigned char headerSize = 0;
    switch (layer) {
        case Link:
            printPacketHeaders = printLinkHeader;
            break;
        case Network:
            printPacketHeaders = printNetworkHeader;
            break;
        case Transport:
            printPacketHeaders = printTransportHeader;
            break;
        case ALL:
            printPacketHeaders = printAllLayers;
            break;
        default:
            printPacketHeaders = printAllLayers;
    }
    while (true) {
        dataSize = recvfrom(sock, packetBuf, PACKET_SIZE, 0, &s_addr, (socklen_t *) &s_addr_size);
        if (dataSize < 0) {
            perror("Error receiving packets\n");
            gracefulExit(EXIT_FAILURE);
            return;
        }
        headerSize = printPacketHeaders(packetBuf);
        printPayload(packetBuf, dataSize, headerSize);
    }
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "?help")) != -1) {
        if (opt == '?') {
            printf(USAGE_MSG);
            exit(EXIT_SUCCESS);
        }
    }
    struct sigaction sa = {};
    sa.sa_handler = &gracefulExit;
    if (sigaction(SIGINT, &sa, NULL) != 0) {
        perror("Error installing SIGINT action\n");
        exit(EXIT_FAILURE);
    }
    enum Layer layer = ALL;
    if (argc == 2) layer = strtol(argv[1], NULL, 10);
    printPackets(layer);
}