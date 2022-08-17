#include "util.h"

uint8_t* get_host_mac(ifreq ifr, ifconf ifc, char* interface_name){
    
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    strcpy(ifr.ifr_name, interface_name);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
		if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
			if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
				success = 1;
			}
		}
	}
	else { /* handle error */ }

    static uint8_t mac_address[6];
	char* ip;

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);

	return mac_address;
}

char* get_host_ip(ifreq ifr, char* interface_name){
	size_t if_name_len=strlen(interface_name);
	if (if_name_len<sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, interface_name, if_name_len);
		ifr.ifr_name[if_name_len] = 0;
	} else {
		printf("interface name is too long");
	}

	int fd = socket(AF_INET,SOCK_DGRAM,0);
	if (fd == -1) {
		printf("%s", strerror(errno));
	}
	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		int temp_errno = errno; 
		close(fd);
		printf("%s", strerror(temp_errno));
	}

	close(fd);

	struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
	static char ip_addr_str[15];
	inet_ntop(AF_INET, &ipaddr->sin_addr, ip_addr_str, sizeof(ip_addr_str));
	//  inet_ntop(AF_INET,&addr.s_addr,buf,sizeof(buf));

	return ip_addr_str;
}

Mac get_sender_mac(pcap_t* handle, char* sender_ip, char* attacker_ip, uint8_t* attacker_mac){
	//find my packet
	while(true){
		struct pcap_pkthdr* pkt_header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &pkt_header, &packet);

		if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
        
		EthHdr* ethernet = (EthHdr*)packet;
		Mac rec_mac = ethernet->dmac();
		Mac attk_mac = attacker_mac;

		if(rec_mac != attk_mac){
			continue;
		}

		if(ethernet->type() != ethernet->Arp){
			continue;
		}
		
		packet += sizeof(EthHdr);
		ArpHdr* arp = (ArpHdr*)packet;
		Ip rec_ip = arp->sip();
		Ip sdr_ip = (Ip)sender_ip;

		if(rec_ip != sdr_ip){
			continue;
		}

		printf("[+]%s => [me] : MAC_ADDR RECEIVED SUCCESS!\n", ((std::string)rec_ip).c_str());
		printf("[+]RECV: %s\n", ((std::string)ethernet->smac()).c_str());
		return ethernet->smac();
	}
	return Mac::nullMac();
}