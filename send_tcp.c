// Author: Juraj Budai
// Login: xbudai02
// Date: 26.3.2025

#include "ipk.h"

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    // Process each 16-bit word in the buffer
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    
    // Add the overflow (carry) to the sum by shifting and masking
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;  // Invert all bits to get the checksum
    return result;
}

unsigned short ipv6_checksum(struct pseudo_header6 *psh, struct tcphdr *tcph, int tcp_len) {
    int psize = sizeof(struct pseudo_header6) + tcp_len;
    char *pseudogram = malloc(psize);

    if (pseudogram == NULL) {
        perror("Malloc failed");
        return 0;
    }

    // Copy pseudo-header to the pseudogram
    memcpy(pseudogram, psh, sizeof(struct pseudo_header6));

    // Copy TCP header to the pseudogram
    memcpy(pseudogram + sizeof(struct pseudo_header6), tcph, tcp_len);

    // Compute checksum over the pseudogram
    unsigned short result = checksum((unsigned short *)pseudogram, psize);

    free(pseudogram);
    return result;
}

void* send_syn_packet() {
    // Second sending will be done after the receive function has ended
    sem_wait(&sem4);
    if(packet_count4 != 0){
        usleep(100000); 

        for (int i = 0; i < MAX_PORTS; i++)
        {
            if (tcp_ports4[i] == 1)
            {
                char packet[PACKET_SIZE];
                struct iphdr *iph = (struct iphdr *)packet;
                struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
            
                memset(packet, 0, PACKET_SIZE);
                
                int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
                    if (sock < 0) {
                        perror("Error creating socket");
                        return NULL;
                    }
            
                // Set the IP_HDRINCL option to indicate that the IP header is included in the packet
                int one = 1;
                if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) {
                    perror("Error setting IPH_HDRINCL sockopt");
                    return NULL;
                }
                
                // Set up the IP header
                iph->ihl = 5;
                iph->version = 4;
                iph->tos = 0;
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                iph->id = htonl(54321);
                iph->frag_off = htons(16384);
                iph->ttl = 64;
                iph->protocol = IPPROTO_TCP;
                iph->check = 0;
                iph->saddr = src_addr.sin_addr.s_addr;
                iph->daddr = dst_addr.sin_addr.s_addr;
            
                // Calculate the checksum for the IP header
                iph->check = checksum((unsigned short *)packet, iph->tot_len >> 1);
            
                // Set up the TCP header
                tcph->source = htons(23456);
                tcph->dest = htons(i);
                tcph->ack_seq = 0;
                tcph->doff = sizeof(struct tcphdr)/4;
                tcph->syn = 1;
                tcph->window = htons(14600);
                tcph->seq = rand();
                tcph->check = 0;
                tcph->urg_ptr = 0;
            
                // Prepare the pseudo header for checksum calculation
                struct pseudo_header psh;
                psh.source_address = iph->saddr;
                psh.dest_address = iph->daddr;
                psh.placeholder = 0;
                psh.protocol = IPPROTO_TCP;
                psh.tcp_length = htons(sizeof(struct tcphdr));
            
                // Allocate memory for the pseudogram (pseudo-header + TCP header)
                int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
                char *pseudogram = malloc(psize);
                memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
                memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
            
                // Calculate the checksum for the TCP header
                tcph->check = checksum((unsigned short *)pseudogram, psize);
                free(pseudogram);
            
                struct sockaddr_in target;
                memset(&target, 0, sizeof(target));
                target.sin_family = AF_INET;
                target.sin_port = htons(i);
                target.sin_addr.s_addr = dst_addr.sin_addr.s_addr;
    
                if (sendto(sock, packet, ntohs(iph->tot_len), 0, (struct sockaddr *)&target, sizeof(target)) < 0) {
                    perror("Error sending SYN packet");
                    close(sock);
                    exit(1);
                }
                close(sock);
            }
            
        }
    }
    usleep(100000);     // Short delay for packets to be received
    packets_sent4 = 1; // Indicate that IPv4 packets have been sent
    
    return NULL;
}

void* send_syn_packet_ipv6() {
    // Second sending will be done after the receive function has ended
    sem_wait(&sem6);
    if (packet_count6 != 0) {
        usleep(100000); 
        
        for (int i = 0; i < MAX_PORTS; i++)
        {
            if (tcp_ports6[i] == 1)
            {
                char packet[PACKET_SIZE];
                struct ip6_hdr *iph = (struct ip6_hdr *)packet;
                struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip6_hdr));
                
                memset(packet, 0, sizeof(packet));
    
                int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
                    if (sock < 0) {
                        perror("Chyba pri vytváraní socketu");
                        return NULL;
                    }
                // Set the IPV6_HDRINCL option to indicate that the IP header is included in the packet
                int one = 1;
                if (setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(one)) != 0) {
                    perror("Error setting IPV6_HDRINCL sockopt");
                    return NULL;
                }
                // IPv6 Header
                iph->ip6_flow = htonl((6 << 28));
                iph->ip6_plen = htons(sizeof(struct tcphdr));
                iph->ip6_nxt = IPPROTO_TCP;
                iph->ip6_hops = 64;
                iph->ip6_src = src6_addr.sin6_addr;
                iph->ip6_dst = dst6_addr.sin6_addr;
    
                char ip6_str[INET6_ADDRSTRLEN];
    
                if (inet_ntop(AF_INET6, &(src6_addr.sin6_addr), ip6_str, INET6_ADDRSTRLEN) == NULL) {
                    perror("inet_ntop failed");
                }
                
                // TCP Header
                tcph->source = htons(12345);
                tcph->dest = htons(i);
                tcph->seq = rand();
                tcph->ack_seq = 0;
                tcph->doff = sizeof(struct tcphdr) / 4;
                tcph->syn = 1;
                tcph->window = htons(14600);
                tcph->check = 0;
                tcph->urg_ptr = 0;
                
                // Pseudo Header for Checksum
                struct pseudo_header6 psh;
                memset(&psh, 0, sizeof(psh));
                psh.source_address = iph->ip6_src;
                psh.dest_address = iph->ip6_dst;
                psh.length = htons(sizeof(struct tcphdr));
                psh.next_header = IPPROTO_TCP;
                
                tcph->check = ipv6_checksum(&psh, tcph, sizeof(struct tcphdr));
                
                struct sockaddr_in6 target;
                memset(&target, 0, sizeof(target));
                target.sin6_family = AF_INET6;
                target.sin6_addr = dst6_addr.sin6_addr;

                // Send packet
                if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&target, sizeof(struct sockaddr_in6)) < 0) {
                    perror("Error sending ipv6 syn packet");
                    close(sock);
                    exit(1);
                }
                
                close(sock);
            }
        }
    }
    usleep(100000);
    packets_sent6 = 1; // Indicate that IPv6 packets have been sent
    return NULL;
}
