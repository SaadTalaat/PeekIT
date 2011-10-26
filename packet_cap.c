#include "global_structures.h"
#include <string.h>
const u_char* eth_grab_packet(char* dev);
void eth_process_packet(struct pcap_pkthdr,const u_char *,struct in_addr gateway,struct in_addr server,char*,char*);


//grabbing a packet using libpcap
const u_char* eth_grab_packet(char* dev){
	pcap_t *handler;
	struct pcap_pkthdr hdr;
	const u_char* packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	char filter_exp[] = "ip";
	int ret;
	bpf_u_int32 netp; 
	bpf_u_int32 maskp;
	char *net;
	printf("	> Detecting remote network devices..\n");
	handler = pcap_open_live(dev,BUFSIZ,1,10000,errbuf);//setting the device on promiscuous mode and setting bufsize  
														//and maximum time to wait to get a response
	if( handler == NULL ){
		fprintf(stderr,"	> Couldn't set card on promiscuous :%s \n",errbuf);
		exit(-1);
	}
	ret = pcap_lookupnet(dev,&netp,&maskp,errbuf);
	if(pcap_compile(handler,&filter,filter_exp,0,netp) == -1 )
	{
		fprintf(stderr,"Failed to make filter\n");
		exit(-1);
	}
	if(pcap_setfilter(handler,&filter) == -1){
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handler));
		exit(-1);
	}
	packet = pcap_next(handler,&hdr);//start packet capturing
	remote_info.curr_hdr = hdr;	// set header to gobal variable
	packet_info.packet = (u_char*)packet;
	return packet;

}

void
eth_process_packet(struct pcap_pkthdr hdr,const u_char *packet,struct in_addr server,struct in_addr gateway
						,char* gatewaystr,char* serverstr){
	 u_int8_t *macs[ETH_ALEN];
	struct ether_header *eptr;
	struct ip *hedr;
	struct	tcphdr *thdr;
	u_char *ptr;
	u_int size_ip;
    u_int size_tcp;
	const char *payload;
	int i,k;
	struct sockaddr_in sock;
	int ret;

	k=0;
	hedr = (struct ip*)(packet+ 14);
	printf("> src ip: %s\n",(unsigned char*)inet_ntoa(hedr->ip_src));
	printf("> dst ip: %s\n",(unsigned char*)inet_ntoa(hedr->ip_dst));

	size_ip = IP_HL(hedr)*4;
	inet_aton("192.168.1.255",&hedr->ip_dst);
	inet_aton("192.168.1.15",&hedr->ip_src);
	printf("> Time to Live %d \n",hedr->ip_ttl);
	thdr = (struct tcphdr*) (packet + size_ip + ETHER_SIZE);
	printf("> source port %d\n",(int)ntohs(thdr->source));
	printf("> destination port %d\n",(int)htons(thdr->dest));
	ret = compare_ip(hedr->ip_src,gateway,server,gatewaystr,serverstr);
	if(ret != 0){
		printf("illegal connection from %s\n",(unsigned char*)inet_ntoa(hedr->ip_src));
	}
	u_int8_t *p;
	p =(u_int8_t*)&thdr->seq;
	printf("> Packet Sequence: %02x%02x%02x%02x\n\n",
	((unsigned char*)p)[0],	
	((unsigned char*)p)[1],
	((unsigned char*)p)[2],
	((unsigned char*)p)[3]);
	size_tcp = TH_OFF(thdr)*4;
	sock.sin_family = AF_INET;
	sock.sin_addr.s_addr = hedr->ip_dst.s_addr;
	sock.sin_port = htons(thdr->source);
	payload = (u_char *)(packet);
//	printf("PACKET %02x %02x %02x\n",
//	((unsigned char *)payload)[0],
//	((unsigned char *)payload)[1],
//	((unsigned char *)payload)[2]);
	int con;
	int size = size_ip+size_tcp+ETHER_SIZE+(sizeof(payload)*10)-2 ;
	for(con=0;con<(size_ip+size_tcp+ETHER_SIZE+(sizeof(payload)*10)-2);con++){
		printf(" %02x",((unsigned char*)payload)[con]);
		if(con%16 == 0 && con != 0) printf("\n>  ");

	}
	printf("\n\n");
	int s;
	if((s = sendto(local_info.sd, packet,size,0,(struct sockaddr *)&sock,(int)sizeof(struct sockaddr_in))) != -1){
		printf("> Successfully sent data \n");
	}
	remote_info.pkt_len = hdr.len;
	remote_info.rec_time = hdr.ts;
	eptr = (struct ether_header *) packet;
	if(ntohs(eptr->ether_type) == ETHERTYPE_IP){
		printf("> Received packet of type IP\n");
	}
	else if(ntohs(eptr->ether_type) == ETHERTYPE_ARP){
		printf("> Received packet of type ARP\n");
	}else{
		printf("> Received packet of unknown type\n");
	}

	packet_info.packet_type = eptr->ether_type;
	packet_info.dhost = eptr->ether_dhost;
	packet_info.shost = eptr->ether_shost;
	ptr = eptr->ether_shost;
	i = ETHER_ADDR_LEN;
	printf("> Source Address: ");
	do{
		printf("%s%02x",(i == ETHER_ADDR_LEN)?" ":":",(unsigned char)*ptr++);
	} while(--i > 0);	
	printf("\n");
	printf("> Destination Address: ");
	ptr = eptr->ether_dhost;
	i = ETHER_ADDR_LEN;
	do{
		printf("%s%02x",(i == ETHER_ADDR_LEN)?" ":":",(unsigned char) *ptr++);
	} while(--i>0);
	printf("\n");
	

	macs[k]=eptr->ether_dhost;
	macs[k+=1]=eptr->ether_shost;
	eth_grab_packet(local_info.dev);
	
	
}
compare_ip(struct in_addr src,struct in_addr server,struct in_addr gateway,char *gatewaystr,char* serverstr){
	if( strcmp(gatewaystr,inet_ntoa(gateway)) || strcmp(serverstr,inet_ntoa(server))){
		return 0;
	}
	return 1;
}
