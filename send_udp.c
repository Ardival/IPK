// Author: Juraj Budai
// Login: xbudai02
// Date: 26.3.2025

#include "ipk.h"

void* send_udp_packet() {
    for (int i = 0; i < MAX_PORTS; i++)
    {
        if (udp_ports4[i] == 1)
        {
            char packet[PACKET_SIZE] = {"hello"};   // Packet payload to send

            int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (sock < 0) {
                printf("Chyba pri vytváraní udp socketu port: %d\n", i);
                return NULL;
            }
            struct sockaddr_in target;
            memset(&target, 0, sizeof(target));
            target.sin_family = AF_INET;
            target.sin_port = htons(i);
            target.sin_addr.s_addr = dst_addr.sin_addr.s_addr;
            
            // Attempt to connect the socket to the target address and port
            if (connect(sock, (struct sockaddr *)&target, sizeof(struct sockaddr_in)) < 0) {
                printf("Chyba pri pripojení ipv4 UDP socketu port: %d\n", i);
                close(sock);
                exit(1);
            }

            // Send the UDP packet to the target
            if (send(sock, packet, sizeof(packet), 0) < 0) {
                printf("Chyba pri odosielaní UDP paketu port: %d\n", i);
                return NULL;
            }
            // Set the socket option to specify a receive timeout
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

            char buffer[PACKET_SIZE];
            int bytes_received = recv(sock, buffer, sizeof(buffer), 0);
            
            if (bytes_received < 0) {
                // If no response is received within the timeout period, consider the port open
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    printf("%s %d udp open\n",inet_ntoa(dst_addr.sin_addr), i);
                    udp_ports4[i] = 0;
                } else {
                    printf("%s %d/udp closed\n",inet_ntoa(dst_addr.sin_addr), i);    // ICMP received, port is closed
                    udp_ports4[i] = 0;
                }
            } else {
                printf("%s %d/udp open\n",inet_ntoa(dst_addr.sin_addr), i);  // Received data, port is open
                udp_ports4[i] = 0;
            }

            close(sock);
        }
    }
    return NULL;
}

void* send_udp_packet_ipv6() {
    for (int i = 0; i < MAX_PORTS; i++)
    {
        if (udp_ports6[i] == 1)
        {
            char packet[PACKET_SIZE] = {"hello"};  // Packet payload to send

            int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
                if (sock < 0) {
                    perror("Chyba pri vytváraní socketu");
                    return NULL;
                }

            struct sockaddr_in6 target;
            memset(&target, 0, sizeof(target));
            target.sin6_family = AF_INET6;
            target.sin6_port = htons(i);
            target.sin6_addr = dst6_addr.sin6_addr;

            if (connect(sock, (struct sockaddr *)&target, sizeof(struct sockaddr_in6)) < 0) {
                printf("Chyba pri pripojení UDP socketu port: %d\n", i);
                close(sock);
                exit(1);
            }

            // Send the UDP packet to the target
            if (send(sock, packet, sizeof(packet), 0) < 0) {
                printf("Chyba pri odosielaní ipv6 UDP paketu port: %d\n", i);
                return NULL;
            }

            // Set the socket option to specify a receive timeout
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

            char buffer[PACKET_SIZE];
            
            int bytes_received = recv(sock, buffer, sizeof(buffer), 0);
            
            char ipv6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &dst6_addr.sin6_addr, ipv6_str, sizeof(ipv6_str));
            
            if (bytes_received < 0) {
                // If no response is received within the timeout period, consider the port open
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    printf("%s %d/udp open\n",ipv6_str, i);
                    udp_ports6[i] = 0;
                } else {
                    printf("%s %d/udp closed\n",ipv6_str, i);    // ICMP received, port is closed
                    udp_ports6[i] = 0;
                }
            } else {
                printf("%s %d/udp open\n",ipv6_str, i);  // Received data, port is open
                udp_ports6[i] = 0;
            }
            
            close(sock);
        }
    }
    
    return NULL;
}
