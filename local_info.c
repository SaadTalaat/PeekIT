#include "global_structures.h"

struct ifreq eth_init(char*,struct ifreq);
struct ifreq eth_get_info(struct ifreq);
struct ifreq eth_get_bcast(struct ifreq);
char* eth_get_dev();
struct ifreq
eth_init(char *dev,struct ifreq ifr){
	//Intitating Socket descriptor of type RAW Packet ipv4    	
	if((local_info.sd = socket(PF_INET,SOCK_PACKET,(ETH_P_ALL))) < 0){
        printf("> Error initating the ethernet socket..\n");
        exit(-1);
    }
	//Successfully opened a descriptor for Ethernet level connection
    printf("> Initated Ethernet socket on Descriptor (%x)\n",local_info.sd);
	return ifr;
}
struct ifreq
eth_get_info(struct ifreq ifr){
	// get local info like (MACAddr,IP,MTU,MASK,BCAST)	
	int i = ETHER_ADDR_LEN;
	char* ptr;
	//reset the ifr bytes
	memset(&ifr,0,sizeof(ifr));
	//copy the device name to the global structure local_info
	strncpy(ifr.ifr_name,local_info.dev,sizeof(ifr.ifr_name));
	//Getting MAC Address using ioctl
	if(ioctl(local_info.sd,SIOCGIFHWADDR,&ifr) < 0){
        	printf("> Error Getting the Local Mac address\n");
        	exit(-1);
    	}
	// Successfully got the MAC address and printing it...
	printf("> Successfully received Local MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",
                (unsigned char)ifr.ifr_hwaddr.sa_data[0],
				(unsigned char)ifr.ifr_hwaddr.sa_data[1],
				(unsigned char)ifr.ifr_hwaddr.sa_data[2],
                (unsigned char)ifr.ifr_hwaddr.sa_data[3],
				(unsigned char)ifr.ifr_hwaddr.sa_data[4],
				(unsigned char)ifr.ifr_hwaddr.sa_data[5]);
	// copy the mac address to the global structure local_info
    memcpy(&(local_info.eth),&ifr.ifr_hwaddr.sa_data,ETH_ALEN);


	// Getting IP Address
        memset(&ifr,0,sizeof(ifr));
        strncpy(ifr.ifr_name,local_info.dev,sizeof(ifr.ifr_name));
		//Getting IP using ioctl
        if( ioctl(local_info.sd,SIOCGIFADDR,&ifr) < 0){ 
                printf("> Error gettint the local IP address\n");
                exit(-1);
        }   
		//Successfully got an IP and printing it
        printf("> Successfully received the IP Address %s\n",
			inet_ntoa((*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr));
        memcpy(&(local_info.ip.s_addr),&(*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr.s_addr,IP_ADDR_LEN);

	        // Get MTU
        memset(&ifr,0,sizeof(ifr));
        strncpy(ifr.ifr_name,local_info.dev,sizeof(ifr.ifr_name));
		//Get MTU using ioctl function
        if ( ioctl(local_info.sd,SIOCGIFMTU,&ifr) < 0){
                printf("> Error Getting the MTU Value\n");
                exit(-1);
        }
		//Successfully got an MTU and printing...
        printf("> Recevied Successfully the MTU Value (%d)bits \n",ifr.ifr_mtu);
        local_info.mtu = ifr.ifr_mtu;


	return ifr;
}

struct ifreq
eth_get_bcast(struct ifreq ifr){
		/* get broadcast addr for network */
        memset(&ifr,0,sizeof(ifr));
        strncpy(ifr.ifr_name, local_info.dev, sizeof (ifr.ifr_name));
		//getting the broadcast address using ioctl
        if (ioctl(local_info.sd, SIOCGIFBRDADDR, &ifr) < 0 ) { 
           printf("> Error getting the Broadcast address\n");
           exit(-1);
        }
		//Successfully received Broadcast address and printing...
        printf("> Received the BroadCast address: %s\n",inet_ntoa((*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr));
        memcpy(&(local_info.bcast.s_addr),
               &(*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr.s_addr,
               IP_ADDR_LEN);

	return ifr;
}
// GET default network interface device using libpcap
char* eth_get_dev(){
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	dev = pcap_lookupdev(errbuf);//getting the device name
	if(dev == NULL){
		fprintf(stderr,"Cloudn't detect a default network device, please enter your device as argument\n");
		exit(-1);
	}
	return dev;
}

