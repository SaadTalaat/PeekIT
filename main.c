/*
** Author : Saad Talaat
** Organization : CATReloaded
** Project : The spoofer goopher
*/

#include "global_structures.h"
#include "local_info.c"
#include "packet_cap.c"


int
main(int argc,char **argv){
    int sd; // Socket descriptor
    struct ifreq ifr; // interface request
	const u_char* packet; // captured packet
	struct in_addr gateway;
	struct in_addr server;
	int count;
	int c;
	opterr = 0;
	int iflag=0,cflag=0;
	char *cgateway,*cserver;
	while((c = getopt (argc,argv,"c:g:s:i:")) != -1){
		switch (c){
			case 'i':
				iflag =1;
				local_info.dev = optarg;
		//		printf("%s\n",optarg);
				break;
			case 'g':
				cgateway=optarg;
				printf("%s\n",cgateway);
				break;
			case 's':
				cserver=optarg;
				printf("%s\n",cserver);
				break;
			case 'c':
				count = atoi(optarg);
				break;
			case '?':
				if(optopt =='c' || optopt == 'i' || optopt == 'g' || optopt=='s'){
					printf("option -%c requires argument\n",optopt);
					return 1;
				} else{
					printf("%s",help);
				}
			default:
				printf("%s",help);
				return 1;


		}
	
	}
	if(!iflag){
		printf("The device must be passed as -i argument\n");
		printf("%s",help);
		return 1;
	} else if(count <=0){
		printf("Invalid Packet count input\n");
		printf("%s",help);
		return 1;
	}
/*
	if(argc != 5){
		printf("> Usage: %s <interface> <gateway ip> <server ip> <count>\n",argv[0]);
		return 0;
		local_info.dev = eth_get_dev(); // get interface using libpcap pcap_lookupdev mostly eth0(linux)
										// or em0(BSD) or eri0(SunOS)
	} else {
		printf("> Default network interface was manually defined..\n");
		local_info.dev = argv[1]; // manually identified interface like lo interface
	}
	if(( count = atoi(argv[4]) ) <= 0){
		printf("> Invalid count passed, count has to be more than 0\n");
	}*/
	printf("Device is %s\n",local_info.dev);
	ifr = eth_init(local_info.dev,ifr);//get primary local values for ifr 
	ifr = eth_get_info(ifr);// get local (MACAddr,IP,MTU,MASK)
	ifr = eth_get_bcast(ifr);// getting Broadcast address
	while(count !=0){
		count--;
                printf("--------------- Grabbing packet --------------------\n");
		do{
			packet = eth_grab_packet(local_info.dev);
		} while(packet == NULL);
		printf("> Successfully grabbed a packet\n");
		inet_aton(argv[3],&server);
		inet_aton(argv[2],&gateway);
		eth_process_packet(remote_info.curr_hdr,packet_info.packet,server,gateway,cgateway,cserver);
	}
	printf("> Exiting...\n");
	return(0);
}



