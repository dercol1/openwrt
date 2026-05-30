#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

#define WOL_PORT 9
#define MAC_LEN 6
#define PACKET_LEN (MAC_LEN + MAC_LEN * 16)

// Converte una stringa MAC "AA:BB:CC:DD:EE:FF" in un array di 6 byte
int parse_mac(const char *mac_str, unsigned char *mac) {
    unsigned int tmp[MAC_LEN];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
               &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]) != MAC_LEN) {
        return -1;
    }
    for (int i = 0; i < MAC_LEN; i++) {
        mac[i] = (unsigned char)tmp[i];
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <MAC_ADDRESS>\n", argv[0]);
        fprintf(stderr, "Esempio: %s AA:BB:CC:DD:EE:FF\n", argv[0]);
        return EXIT_FAILURE;
    }

    unsigned char mac[MAC_LEN];
    if (parse_mac(argv[1], mac) < 0) {
        fprintf(stderr, "Errore: Formato MAC non valido. Usa XX:XX:XX:XX:XX:XX\n");
        return EXIT_FAILURE;
    }

    // Costruzione del Magic Packet
    unsigned char packet[PACKET_LEN];
    // I primi 6 byte sono 0xFF
    memset(packet, 0xFF, MAC_LEN);
    // Seguono 16 ripetizioni del MAC address
    for (int i = 0; i < 16; i++) {
        memcpy(&packet[MAC_LEN + (i * MAC_LEN)], mac, MAC_LEN);
    }

    // Creazione del socket UDP
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Errore creazione socket");
        return EXIT_FAILURE;
    }

    // Abilita l'invio di pacchetti broadcast sul socket
    int broadcast_enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) < 0) {
        perror("Errore setsockopt SO_BROADCAST");
        close(sockfd);
        return EXIT_FAILURE;
    }

    // Enumera tutte le interfacce di rete
    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0) {
        perror("Errore getifaddrs");
        close(sockfd);
        return EXIT_FAILURE;
    }

    int interfacce_usate = 0;

    // Itera su tutte le interfacce
    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        // Salta se non c'è indirizzo, se non è IPv4, se è disattivata o se è di loopback
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_BROADCAST)) continue;

        struct sockaddr_in *bc_addr = (struct sockaddr_in *)ifa->ifa_broadaddr;
        if (bc_addr == NULL) continue;

        // Prepara la struttura di destinazione
        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(WOL_PORT);
        dest_addr.sin_addr = bc_addr->sin_addr; // Invia al broadcast specifico dell'interfaccia

        // Invio del pacchetto
        ssize_t sent = sendto(sockfd, packet, PACKET_LEN, 0, 
                              (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        
        if (sent < 0) {
            fprintf(stderr, "Errore invio su interfaccia %s: ", ifa->ifa_name);
            perror("");
        } else {
            printf("Inviato Magic Packet per %s su %s (Broadcast: %s)\n", 
                   argv[1], ifa->ifa_name, inet_ntoa(dest_addr.sin_addr));
            interfacce_usate++;
        }
    }

    freeifaddrs(ifap);
    close(sockfd);

    if (interfacce_usate == 0) {
        fprintf(stderr, "Attenzione: Nessuna interfaccia di broadcast trovata o utilizzabile.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
