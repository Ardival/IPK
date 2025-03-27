// Author: Juraj Budai
// Login: xbudai02
// Date: 26.3.2025

#ifndef __IPK_H__
#define __IPK_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <pthread.h>
#include <netdb.h>
#include <pcap.h>
#include <semaphore.h>

#define MAX_PORTS 65535
#define PACKET_SIZE 1280

/** Arrays storing TCP/UDP ports to be scanned for IPv4 and IPv6. */
extern int tcp_ports4[MAX_PORTS];  
extern int udp_ports4[MAX_PORTS];
extern int tcp_ports6[MAX_PORTS];  
extern int udp_ports6[MAX_PORTS]; 
/** Adresses for filling the packet*/
extern struct sockaddr_in dst_addr;
extern struct sockaddr_in6 dst6_addr;
extern struct sockaddr_in src_addr;
extern struct sockaddr_in6 src6_addr;
/** Semaphores to stop race condition*/
extern sem_t sem4, sem6;

/** Timeout configuration for packet response. */
extern struct timeval timeout;

/** Counters for sent packets and overall packet counts for IPv4 and IPv6. */
extern int packets_sent4;
extern int packets_sent6;
extern int packet_count4;
extern int packet_count6;

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

struct pseudo_header6 {
    struct in6_addr source_address;
    struct in6_addr dest_address;
    uint32_t length;
    uint8_t zero[3];
    uint8_t next_header;
};

/**
 * @brief Sends a TCP SYN packet to a specified IPv4 target.
 * 
 */
void* send_syn_packet();

/**
 * @brief Sends a TCP SYN packet to a specified IPv6 target.
 * 
 */
void* send_syn_packet_ipv6();

/**
 * @brief Sends a UDP packet to a specified IPv4 target.
 * 
 */
void* send_udp_packet();

/**
 * @brief Sends a UDP packet to a specified IPv6 target.
 * 
 */
void* send_udp_packet_ipv6();

/**
 * @brief Computes the checksum for a given buffer.
 * 
 * @param b Pointer to the data buffer.
 * @param len Length of the buffer.
 * @return Computed checksum value.
 */
unsigned short checksum(void *b, int len);

/**
 * @brief Computes the checksum for an IPv6 TCP packet.
 * 
 * @param psh Pointer to the pseudo-header structure.
 * @param tcph Pointer to the TCP header structure.
 * @param tcp_len Length of the TCP segment.
 * @return Computed checksum value.
 */
unsigned short ipv6_checksum(struct pseudo_header6 *psh, struct tcphdr *tcph, int tcp_len);

/**
 * @brief Retrieves the local IP address for a given network interface.
 * 
 * @param interface Name of the network interface.
 */
void get_local_ip(const char *interface);

/**
 * @brief Parses port numbers from a string argument and stores them in an array.
 * 
 * @param arg Input string containing port numbers (single ports or ranges).
 * @param port_array Array to store parsed port numbers.
 * @param option Specifies protocol (1 for TCP, 2 for UDP).
 */
void parse_ports(char *arg, int *port_array, int option);

/**
 * @brief Prints available network interfaces.
 */
void print_interfaces();

/**
 * @brief Receives incoming data from the network for TCP IPv4 packets.
 * 
 * @return NULL.
 */
void *recv_data();

/**
 * @brief Receives incoming data from the network for TCP IPv6 packets.
 * 
 * @return NULL.
 */
void *recv_data_ipv6();
/**
 * @brief Starts parallel sending and receiving for ipv4
 */
void* send_ipv4();
/**
 * @brief Starts parallel sending and receiving for ipv6
 */
void* send_ipv6();
/**
 * @brief Prints the help message with usage instructions.
 */
void print_help();


#endif