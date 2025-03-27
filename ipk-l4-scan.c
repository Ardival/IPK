// Author: Juraj Budai
// Login: xbudai02
// Date: 26.3.2025

#include "ipk.h"

int tcp_ports4[MAX_PORTS] = {0};  
int udp_ports4[MAX_PORTS] = {0};
int tcp_ports6[MAX_PORTS] = {0};  
int udp_ports6[MAX_PORTS] = {0}; 
struct sockaddr_in dst_addr;
struct sockaddr_in6 dst6_addr;
struct sockaddr_in src_addr;
struct sockaddr_in6 src6_addr;
struct timeval timeout;
int packets_sent4 = 0;
int packets_sent6 = 0;
int packet_count4 = 0;
int packet_count6 = 0;
int ipv4_option = 1;
int ipv6_option = 2;
sem_t sem4, sem6;

void* send_ipv4(){

    pthread_t tcp_thread, udp_thread, receive_th;
    if (pthread_create(&receive_th, NULL, recv_data, NULL) != 0) {
        fprintf(stderr, "Error: pthread_create for Receive thread failed\n");
        exit(1);
    }

    if (pthread_create(&udp_thread, NULL, send_udp_packet, NULL) != 0) {
        fprintf(stderr, "Error: pthread_create for UDP thread failed\n");
        exit(1);
    }

    if (pthread_create(&tcp_thread, NULL, send_syn_packet, NULL) != 0) {
        fprintf(stderr, "Error: pthread_create for TCP thread failed\n");
        exit(1);
    }

    if (pthread_join(tcp_thread, NULL) != 0) {
        fprintf(stderr, "Error: pthread_join for TCP thread failed\n");
    }

    if (pthread_join(receive_th, NULL) != 0) {
        fprintf(stderr, "Error: pthread_join for Receive thread failed\n");
    }

    if (pthread_join(udp_thread, NULL) != 0) {
        fprintf(stderr, "Error: pthread_join for UDP thread failed\n");
    }

    return NULL;
}

void* send_ipv6(){
    
    pthread_t tcp_thread, udp_thread, receive_th;
    if (pthread_create(&receive_th, NULL, recv_data_ipv6, NULL) != 0) {
        fprintf(stderr, "Error: pthread_create for Receive thread failed\n");
        exit(1);
    }

    if (pthread_create(&udp_thread, NULL, send_udp_packet_ipv6, NULL) != 0) {
        fprintf(stderr, "Error: pthread_create for UDP thread failed\n");
        exit(1);
    }

    if (pthread_create(&tcp_thread, NULL, send_syn_packet_ipv6, NULL) != 0) {
        fprintf(stderr, "Error: pthread_create for TCP thread failed\n");
        exit(1);
    }

    if (pthread_join(tcp_thread, NULL) != 0) {
        fprintf(stderr, "Error: pthread_join for TCP thread failed\n");
    }

    if (pthread_join(receive_th, NULL) != 0) {
        fprintf(stderr, "Error: pthread_join for Receive thread failed\n");
    }

    if (pthread_join(udp_thread, NULL) != 0) {
        fprintf(stderr, "Error: pthread_join for UDP thread failed\n");
    }

    return NULL;
}

void get_local_ip(const char *interface) {
    
    struct ifaddrs *ifa, *ifa_tmp;
    char src_ip[INET6_ADDRSTRLEN];
    
    if (getifaddrs(&ifa) == -1) {
        perror("getifaddrs failed");
        exit(1);
    }
    ifa_tmp = ifa;
    while (ifa_tmp) {
        // Check if the interface has an address and if it matches the requested interface
        if ((ifa_tmp->ifa_addr) && ((ifa_tmp->ifa_addr->sa_family == AF_INET) ||
                                (ifa_tmp->ifa_addr->sa_family == AF_INET6)) && strcmp(interface, ifa_tmp->ifa_name) == 0) {
            if (ifa_tmp->ifa_addr->sa_family == AF_INET) {
                // create IPv4 string
                struct sockaddr_in *in = (struct sockaddr_in*) ifa_tmp->ifa_addr;
                inet_ntop(AF_INET, &in->sin_addr, src_ip, INET_ADDRSTRLEN);
                src_addr.sin_addr = in->sin_addr;   // Store in global IPv4 source address structure
                
            } else { // AF_INET6
                // create IPv6 string
                struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa_tmp->ifa_addr;
                inet_ntop(AF_INET6, &in6->sin6_addr, src_ip, INET6_ADDRSTRLEN);
                src6_addr.sin6_addr = in6->sin6_addr;   // Store in global IPv6 source address structure
            }
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }

    freeifaddrs(ifa);
    return;
}

void print_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Chyba pri získavaní zoznamu rozhraní: %s\n", errbuf);
        return;
    }

    printf("Dostupné sieťové rozhrania:\n");
    for (d = alldevs; d; d = d->next) {
        printf(" - %s\n", d->name);
    }

    pcap_freealldevs(alldevs);
}

void print_help() {
    printf("\033[1;32mUsage:\033[0m\n");
    printf("  ./ipk-l4-scan [options] \n\n");

    printf("\033[1;34mMandatory:\033[0m\n");
    printf("  \033[1;33m-i <interface>\033[0m | \033[1;33m--interface <interface>\033[0m\n");
    printf("    Specify the network interface. If not provided, active interfaces are listed.\n\n");

    printf("  \033[1;33m--pt <ports>\033[0m | \033[1;33m--pu <ports>\033[0m | \033[1;33m-t <ports>\033[0m | \033[1;33m-u <ports>\033[0m\n");
    printf("    Specify TCP (-t, --pt) or UDP (-u, --pu) port ranges to scan.\n");
    printf("    Example: --pt 22  |  --pu 1-65535  |  --pt 22,23,24\n");
    printf("    TCP and UDP arguments can be used separately.\n\n");

    printf("  \033[1;33m<hostname|ip-address>\033[0m\n");
    printf("    Target device to scan. Either a hostname or an IPv4/IPv6 address.\n\n");

    printf("\033[1;34mOptional:\033[0m\n");
    printf("  \033[1;33m-w <timeout>\033[0m | \033[1;33m--wait <timeout>\033[0m\n");
    printf("    Set timeout (in milliseconds) for waiting on a single port scan.\n\n");

}

void parse_ports(char *arg, int *port_array, int option) {
    char *token = strtok(arg, ",");  // Split input by ","
    
    while (token){
        if (strchr(token, '-')) {   // Check if the token contains a range (e.g. 1000-2000)
            int start, end;
            if (sscanf(token, "%d-%d", &start, &end) == 2) {
                // Validate the range
                if (start > end || start < 1 || end > 65535) {
                    fprintf(stderr, "Invalid port range: %s\n", token);
                    exit(1);
                }
                // Mark all ports within the range
                for (int p = start; p <= end; p++) {
                    port_array[p] = 1;
                    if(option == 1){
                        packet_count4++;
                        packet_count6++;
                    }
                }
            } else {
                fprintf(stderr, "Invalid range format: %s\n", token);
                exit(1);
            }
        } else {    // Single port case
            int port = atoi(token);
            if (port < 1 || port > 65535) {
                fprintf(stderr, "Invalid port number: %s\n", token);
                exit(1);
            }
            port_array[port] = 1;
             if(option == 1){
                packet_count4++;
                packet_count6++;
            }
        }
        token = strtok(NULL, ",");
    }
}

/**
 * This function processes the input arguments, initializes relevant settings such as 
 * the network interface, timeout value, and ports for scanning. It then resolves the target host
 * to either an IPv4 or IPv6 address, and creates threads to receive data while sending packets 
 * to the target based on the selected protocol.
 */
int main(int argc, char const *argv[])
{
    const char *interface = NULL;
    const char *target_host = NULL; // Target host for the scan (hostname or IP)
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    for (int i = 1; i < argc; i++){

        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0){

            if (i + 1 < argc) {
                // Set interface if provided
                interface = argv[++i];
            } else {
                // If no interface specified, print available interfaces and exit
                print_interfaces();
                return 0;
            }
        } 
        // Handle timeout value
        else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc){
            int set_time = atoi(argv[++i]);
            if (set_time <= 0)
            {
                fprintf(stderr, "Nedovolene cislo pre timeout\n");
                exit(1);
            }

            timeout.tv_usec = set_time * 1000;
            timeout.tv_sec = 0;
        } 
        // Handle TCP port range
        else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--pt") == 0) && i + 1 < argc){
            parse_ports((char *)argv[++i], tcp_ports4, 1);
            memcpy(tcp_ports6, tcp_ports4, sizeof(tcp_ports4));
        } 
        // Handle UDP port range
        else if ((strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--pu") == 0) && i + 1 < argc){
            parse_ports((char *)argv[++i], udp_ports4, 2);
            memcpy(udp_ports6, udp_ports4, sizeof(udp_ports4));
        } 
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0){
            print_help();
            return 0;
        } 
        // The first non-option argument is the target host
        else if (target_host == NULL) {
            target_host = argv[i];
        }
    }

    // Get local IP address for the specified interface
    get_local_ip(interface);
    
    if (target_host != NULL)
    {
        sem_init(&sem4, 0, 1);
        sem_init(&sem6, 0, 1);
        // Attempt to parse target_host as IPv4 address
        if (inet_pton(AF_INET, target_host, &(dst_addr.sin_addr)) == 1) {

            send_ipv4();
            
            memset(udp_ports4, 0, sizeof(udp_ports4));
            
            // Second call (only starts after the first one is done)
            send_ipv4();

            for (int i = 0; i < MAX_PORTS; i++)
            {
                if(tcp_ports4[i] == 1){
                    printf("%s %d tcp filtered\n", inet_ntoa(dst_addr.sin_addr), i);
                }
            }
            
    
        } 
        //Attempt to parse target_host as IPv6 address
        else if (inet_pton(AF_INET6, target_host, &(dst6_addr.sin6_addr)) == 1) {
            
            send_ipv6();
           
            memset(udp_ports6, 0, sizeof(udp_ports6));
           
            // Second call (only starts after the first one is done)
            send_ipv6();
            
            char ipv6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &dst6_addr.sin6_addr, ipv6_str, sizeof(ipv6_str));
            for (int i = 0; i < MAX_PORTS; i++)
            {
                if(tcp_ports6[i] == 1){
                    printf("%s %d tcp filtered\n", ipv6_str, i);
                }
            }

        } else {
            // If it's neither IPv4 nor IPv6, try to resolve the hostname to IP
            struct addrinfo hints, *res;
            memset(&hints, 0, sizeof(hints));
            hints.ai_socktype = SOCK_STREAM;

            hints.ai_family = AF_INET;
            if (getaddrinfo(target_host, NULL, &hints, &res) == 0) {
                memcpy(&dst_addr, res->ai_addr, sizeof(struct sockaddr_in));
                freeaddrinfo(res);  // Successfully resolved IPv4
            }

            hints.ai_family = AF_INET6;
            if (getaddrinfo(target_host, NULL, &hints, &res) == 0) {
                memcpy(&dst6_addr, res->ai_addr, sizeof(struct sockaddr_in6));
                freeaddrinfo(res); // Successfully resolved IPv6
            }

            pthread_t thread1, thread2;

            if (pthread_create(&thread1, NULL, send_ipv4, NULL) != 0) {
                fprintf(stderr, "Error: pthread_create for IPv4 thread failed\n");
                return 1;
            }
        
            if (pthread_create(&thread2, NULL, send_ipv6, NULL) != 0) {
                fprintf(stderr, "Error: pthread_create for IPv6 thread failed\n");
                return 1;
            }
        
            if (pthread_join(thread1, NULL) != 0) {
                fprintf(stderr, "Error: pthread_join for IPv4 thread failed\n");
            }
        
            if (pthread_join(thread2, NULL) != 0) {
                fprintf(stderr, "Error: pthread_join for IPv6 thread failed\n");
            }
        
            memset(udp_ports4, 0, sizeof(udp_ports4));  // Set udp ports to 0, for not sending again
            memset(udp_ports6, 0, sizeof(udp_ports6));
        
            if (pthread_create(&thread1, NULL, send_ipv4, NULL) != 0) {
                fprintf(stderr, "Error: pthread_create for IPv4 thread failed\n");
                return 1;
            }
        
            if (pthread_create(&thread2, NULL, send_ipv6, NULL) != 0) {
                fprintf(stderr, "Error: pthread_create for IPv6 thread failed\n");
                return 1;
            }
        
            if (pthread_join(thread1, NULL) != 0) {
                fprintf(stderr, "Error: pthread_join for IPv4 thread failed\n");
            }
        
            if (pthread_join(thread2, NULL) != 0) {
                fprintf(stderr, "Error: pthread_join for IPv6 thread failed\n");
            }
            char ipv6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &dst6_addr.sin6_addr, ipv6_str, sizeof(ipv6_str));
            for (int i = 0; i < MAX_PORTS; i++)
            {
                if(tcp_ports4[i] == 1){
                    printf("%s %d tcp filtered\n", inet_ntoa(dst_addr.sin_addr), i);
                }
                if(tcp_ports6[i] == 1){
                    printf("%s %d tcp filtered\n", ipv6_str, i);
                }
            }
        }
        sem_destroy(&sem4);
        sem_destroy(&sem6);
    }
    return 0;
}
