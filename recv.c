// Author: Juraj Budai
// Login: xbudai02
// Date: 26.3.2025

#include "ipk.h"

void *recv_data() {
    
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock < 0) {
        perror("Cannot create raw socket for receive");
        exit(1);
    }
    // Set a timeout for the socket receive operation
    if (setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        close(raw_sock);
        exit(1);
    }
    // Buffer to store the received packet (IP header + TCP header)
    unsigned char buf[sizeof(struct iphdr) + sizeof(struct tcphdr)];

    struct iphdr *iph = (struct iphdr *)buf;
    struct tcphdr *tcph = (struct tcphdr *)(buf + sizeof(struct iphdr));

    // Do till all packets are processed
    while (!packets_sent4 && packet_count4 > 0) {

        if (recvfrom(raw_sock, buf, sizeof(buf), 0, NULL, NULL) < 0) {
            // Handle error or timeout (EAGAIN, EWOULDBLOCK indicates no data)
            if (!(errno == EAGAIN || errno == EWOULDBLOCK)) {
                perror("recvfrom error");
                return NULL;
            }
            continue;
        }
        if (iph->saddr == dst_addr.sin_addr.s_addr && iph->protocol == IPPROTO_TCP) {
            // If the packet is a SYN-ACK, the port is open
            if (tcph->syn == 1 && tcph->ack == 1) {
                printf("%s %d tcp open\n", inet_ntoa(dst_addr.sin_addr), htons(tcph->source));
                tcp_ports4[htons(tcph->source)] = 0;
                packet_count4--;
            } 
            // If the packet is a RST-ACK, the port is closed
            else if (tcph->rst == 1 && tcph->ack == 1) {
                printf("%s %d tcp closed\n", inet_ntoa(dst_addr.sin_addr), htons(tcph->source));
                tcp_ports4[htons(tcph->source)] = 0;
                packet_count4--;
            }
        }
    }
    close(raw_sock);
    packets_sent4 = 0;
    sem_post(&sem4);    // Ready for second send
    
    return NULL;
}

void *recv_data_ipv6() {
   
    socklen_t addr_len = sizeof(src6_addr);
    char buffer[150];
    char ipv6_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &dst6_addr.sin6_addr, ipv6_str, sizeof(ipv6_str));
    
    // Create a raw socket for IPv6 packets
    int raw_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock < 0) {
        perror("Socket creation failed");
        return NULL;
    }
   
    if (setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        close(raw_sock);
        exit(1);
    }
    
    while (!packets_sent6 && packet_count6 > 0) {
        
        if (recvfrom(raw_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&src6_addr, &addr_len) < 0) {
                // Handle error or timeout (EAGAIN, EWOULDBLOCK indicates no data)
            if (!(errno == EAGAIN || errno == EWOULDBLOCK)) {
                perror("recvfrom error");
                return NULL;
            }
            // Skip invalid packet
            continue;
        }

        struct tcphdr *tcp_header = (struct tcphdr *)(buffer);
        // If the packet is a SYN-ACK, the port is open
        if (tcp_header->syn == 1 && tcp_header->ack == 1)
        {
            printf("%s %d tcp open\n", ipv6_str, htons(tcp_header->source));
            tcp_ports6[htons(tcp_header->source)] = 0;
            packet_count6--;
        } 
        // If the packet is a RST-ACK, the port is closed
        else if (tcp_header->rst == 1 && tcp_header->ack == 1) {
            printf("%s %d tcp closed\n", ipv6_str, htons(tcp_header->source));
            tcp_ports6[htons(tcp_header->source)] = 0;
            packet_count6--;
        }
    }

    close(raw_sock);
    packets_sent6 = 0;
    sem_post(&sem6);    // Ready for second send
    return NULL;
}