#ifndef MAIN_H
#define MAIN_H

#include <cstdio>
#include <pcap.h>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthArpPacket(uint8_t mode, Mac ether_dmac, Mac ether_smac, uint16_t _type, uint16_t _hrd, uint16_t _pro, uint8_t _hln, uint8_t _pln, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip)
    {
        eth_.dmac_ = ether_dmac;
        eth_.smac_ = ether_smac;
        eth_.type_ = htons(EthHdr::Arp);

        arp_.hrd_ = htons(ArpHdr::ETHER);
        arp_.pro_ = htons(EthHdr::Ip4);

        arp_.op_ = htons(mode);

        arp_.hln_ = Mac::SIZE;
        arp_.pln_ = Ip::SIZE;

        arp_.smac_ = arp_smac;
        arp_.sip_ = htonl(arp_sip);
        arp_.tmac_ = arp_tmac;
        arp_.tip_ = htonl(arp_tip);
    }

    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}


#endif // MAIN_H
