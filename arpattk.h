#pragma once

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

#include "mainstruct.h"
#include "util.h"

void arp_request(pcap_t* handle, char* sender_ip, char* attacker_ip, uint8_t* attacker_mac);
void send_arp(pcap_t* handle, EthArpPacket packet);
EthArpPacket set_arp_packet(EthArpPacket packet, char* sender_ip, Mac sender_mac, char* target_ip, char* attacker_ip, uint8_t* attacker_mac);
void* arp_send_attack(void* thread_argv); // thread function

