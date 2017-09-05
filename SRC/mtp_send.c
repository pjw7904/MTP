/*
 * mtp_send.c
 * Peter Willis - MARKED UP FOR MY UNDERSTANDING
 */

//header file which contains function prototypes, and destination MAC addrs (FF) repeated along with the HEADER_SIZE constant
#include "mtp_send.h"


/*
 * This function is called in main.c at line 180 after possibly (if statement) building a JOIN or PERIODIC message.
 * The function call in main is: ctrlSend(interfaceNames[i], payload, payloadlen)
 */
int ctrlSend(char *etherPort, uint8_t *inPayload, int payloadLen) {

	//set to -1 by default, error checking perhaps?
	int frame_Size = -1;

	int sockfd;

	//structure to configure common Linux network device parameters (netmask, mtu, addr, dstaddr, etc).
	struct ifreq if_idx;
	struct ifreq if_mac;

	//IFNAMSIZ - defines the maximum buffer size needed to hold an interface name, including its terminating zero byte.
	char ifName[IFNAMSIZ];

	//ifName = Destination | etherPort = Source, moving the arugment given into the ifName string
	strcpy(ifName, etherPort);
	//HEADER_SIZE = 14, as defined by mtp_send.h | payloadLen is 1 at this point (?)
	frame_Size = HEADER_SIZE + payloadLen;

	// creating frame | 15 bytes if my calculations from above are correct
	uint8_t frame[frame_Size];

	//C lib struct [#include <netinet/ether.h>], defines the 14 byte ENET II header | reserving memory for ENET header
	struct ether_header *eh = (struct ether_header*)calloc(1, sizeof(struct ether_header));

	//C lib struct
	struct sockaddr_ll socket_address;

	//Open RAW socket to send on | IPPROTO_RAW allows you to interface directly with L3 and its payload
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("Socket Error");
	}

	/*void *memset(block of mem to fill, value to fill passed as int, # of bytes to be set to the value)
	 *zeroing out the ifreq struct if_idx, copying ifname to if_idx value int name to every char -1, null byte I assume
	 */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ - 1);
	//unsure, 0 if success. -1 if failure, stands for I/O control
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX - Misprint Compatibility");

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR - Either interface is not correct or disconnected");

	/*
	 *  Ethernet Header - 14 bytes
	 *
	 *  6 bytes - Source MAC Address
	 *  6 bytes - Destination MAC Address
	 *  2 bytes - EtherType
	 *
	 */

	//The "ether_shost" variable is an unsigned char, meaning that each octet is being added to create the full source address (?)
	eh->ether_shost[0] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *) &if_mac.ifr_hwaddr.sa_data)[5];

	//also an unsigned char, the MY_DEST_MACX all point to 0xFF, which would mean the destination is a limited L2 broadcast
	eh->ether_dhost[0] = MY_DEST_MAC0;
	eh->ether_dhost[1] = MY_DEST_MAC1;
	eh->ether_dhost[2] = MY_DEST_MAC2;
	eh->ether_dhost[3] = MY_DEST_MAC3;
	eh->ether_dhost[4] = MY_DEST_MAC4;
	eh->ether_dhost[5] = MY_DEST_MAC5;

	//Finishes the ETH II header, adds in the ethertype for MTP
	eh->ether_type = htons(0x8850);

	// Copying ETH II header defined in the three fields above to the custom frame being built
	memcpy(frame, eh, sizeof(struct ether_header));

	// Copying Payload (No. of tier addr + x times (tier addr length + tier addr) )
	// Copying payLoad to frame
	memcpy(frame + sizeof(struct ether_header), inPayload, payloadLen);

	// Index of the network device
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	// Address length - 6 bytes
	socket_address.sll_halen = ETH_ALEN;

	// Destination MAC Address, why does this have to be done twice?
	socket_address.sll_addr[0] = MY_DEST_MAC0;
	socket_address.sll_addr[1] = MY_DEST_MAC1;
	socket_address.sll_addr[2] = MY_DEST_MAC2;
	socket_address.sll_addr[3] = MY_DEST_MAC3;
	socket_address.sll_addr[4] = MY_DEST_MAC4;
	socket_address.sll_addr[5] = MY_DEST_MAC5;

	/* Send packet
	 * sockfd is the socket being utilized, frame is the message being sent, frame_size is the length of the message
	 * &socket_address is the destination address being used (has to be of struct sockaddr)
	 *
	 */
	if (sendto(sockfd, frame, frame_Size, 0, (struct sockaddr*) &socket_address, sizeof(struct sockaddr_ll)) < 0) {
		printf("ERROR: Send failed\n");
	}

	//free Ethernet memory, close out the socket, and return a successful status code
	free(eh);
	close(sockfd);
	return 0;
}


int dataSend(char *etherPort, uint8_t *inPayload, int payloadLen) {
  int sockfd;
  struct ifreq if_idx;

  struct sockaddr_ll socket_address;

  // Open RAW socket to send on
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
    perror("Socket Error");
  }

  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, etherPort, strlen(etherPort));
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
    perror("SIOCGIFINDEX - Misprint Compatibility");
  }

  // Index of the network device
  socket_address.sll_ifindex = if_idx.ifr_ifindex;

  // Address length - 6 bytes
  socket_address.sll_halen = ETH_ALEN;

  // Send packet
  if (sendto(sockfd, inPayload, payloadLen, 0, (struct sockaddr*) &socket_address, sizeof(struct sockaddr_ll)) < 0) {
    printf("ERROR: Send failed\n");
  }

  close(sockfd);
  return 0;
}
