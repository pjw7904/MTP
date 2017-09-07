/*
 *	Main.c
 *
 *
 *  Created on: Sep 21, 2015
 *  Author: Pranav Sai(pk6420@rit.edu)
 *  Peter Willis - MARKED UP FOR MY UNDERSTANDING
 */

#include <stdio.h>

#include <sys/types.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <signal.h>
#include <ctype.h>

#include "feature_payload.h"
#include "mtp_send.h"

//MTP Ethertype
#define ETH_MTP_CTRL    0x8850

#define MAX_VID_LIST    20

//I belive "172" is a string in this case for comparsion later to check if its a given private address by GENI/control eth0 interface
#define CTRL_IP		"172"

//Function Prototypes
void mtp_start();
int getActiveInterfaces(char **);
void learn_active_interfaces();
bool checkInterfaceIsActive(char *);

//Global variables
bool isRoot = false;
struct interface_tracker_t *interfaceTracker = NULL;

//main function, protocol begins here
int main (int argc, char** argv) {
	char **interfaceNames;

	/*Check number of Arguments, after the program name
	 *A "1" argument means that the switch is the root of a meshed tree, a "0" means that it is a child
	 *If a "1" is specified first, then another argument has to be added that tells the program what the root VID is
	 *Ex: ./mtp 1 1 = I am the root switch, and my VID (the root VID) is 1
	 */
	if (argc < 2) {
		printf("Error: Node spec or ROOT MTS ID missing. Format ./main <non MTS/root MTS> <ROOT MTS ID>\n");
		printf("Error: 0 for non MTS, 1 for root MTS\n");
		exit(1);
	}

	//Check if Node is Root MTS or Non MTS, atoi converts a string argument into an integer (why >= 1 and not == 1?)
	if (atoi(argv[1]) >= 1) {
		isRoot = true;
	}


//----------------------------------------------------------BCAST TABLE START--------------------------------------------------------------------------
	/*
	 *Intially we mark all ports as host ports, if we get a MTP CTRL frame from any port we remove it. The local host broadcast table is populated as a result of the
	 *ports all being host ports
	 */
	interfaceNames = (char**) calloc (MAX_INTERFACES*MAX_INTERFACES, sizeof(char));
	memset(interfaceNames, '\0', sizeof(char) * MAX_INTERFACES * MAX_INTERFACES);
	//returns the number of interfaces
	int numberOfInterfaces = getActiveInterfaces(interfaceNames);

	int i = 0;
	for (; i < numberOfInterfaces; i++) {
		// Allocate memory and intialize(calloc), local_bcast_tuple has two vars: ethernet port name, and a pointer to the next local_bcast_tuple
		struct local_bcast_tuple *new_node = (struct local_bcast_tuple*) calloc (1, sizeof(struct local_bcast_tuple));

		// eth_name is the one var in local_bcast_tuple, which is the destination in the string copy
		strncpy(new_node->eth_name, interfaceNames[i], strlen(interfaceNames[i]));
		new_node->next = NULL;
		add_entry_lbcast_LL(new_node);
	}
//----------------------------------------------------------BCAST TABLE END-----------------------------------------------------------------------------


	// If Node is Root MTS
	if (isRoot) {
		// Check if Root VID is provided through CLI.
		if (argv[2] != NULL) {
			//printf ("ROOT MTVID: %s\n", argv[2]);

			// Allocate memory and intialize(calloc).
			struct vid_addr_tuple *new_node = (struct vid_addr_tuple*) calloc (1, sizeof(struct vid_addr_tuple));

			// Fill data.
			strncpy(new_node->vid_addr, argv[2], strlen(argv[2]));
			strcpy(new_node->eth_name, "self");   	// own interface, so mark it as self, will be helpful while tracking own VIDs.
			new_node->last_updated = -1; 		        // -1 here because root ID should not be removed.
			new_node->port_status = PVID_PORT;
			new_node->next = NULL;
			new_node->isNew = true;
			new_node->path_cost = PATH_COST;

			// Add into VID Table.
			add_entry_LL(new_node);

			i = 0;
			uint8_t *payload = NULL;
			uint8_t payloadLen;

			for (; i < numberOfInterfaces; i++) {
				payload = (uint8_t*) calloc (1, MAX_BUFFER_SIZE);
				payloadLen = build_VID_ADVT_PAYLOAD(payload, interfaceNames[i]);
				if (payloadLen) {
					ctrlSend(interfaceNames[i], payload, payloadLen);
				}
				free(payload);
			}
		} else {
			printf ("Error: Provide ROOT Switch ID ./main <non MTS/root MTS> <ROOT MTS ID>\n");
			exit(1);
		}
	}
	free(interfaceNames);

	// learn all interfaces avaliable.
	learn_active_interfaces();

	// Start
	mtp_start();

	return 0;
}

/* Start MTP Protocol. */
void mtp_start() {
	int sockCtrl = 0, sockData = 0, recv_len = 0;
	uint8_t recvBuffer[MAX_BUFFER_SIZE];
	struct ether_header *eheader = NULL;
	struct sockaddr_ll src_addr;
	char **interfaceNames, **deletedVIDs;

	// time_t, timers for checking hello time.
	time_t time_advt_beg;
	time_t time_advt_fin;

	//convergence time timers
	time_t converge1_beg;
	time_t converge1_fin;

	// clear the memory
	interfaceNames = (char**) calloc (MAX_INTERFACES* MAX_INTERFACES, sizeof(char));
	deletedVIDs = (char**) calloc (MAX_VID_LIST * MAX_VID_LIST, sizeof(char));

	// Create Socket, ETH_MTP_CTRL is used because we are listening packets of all kinds.
	if ((sockCtrl = socket(AF_PACKET, SOCK_RAW, htons (ETH_MTP_CTRL))) < 0) {
		perror("Error: MTP socket()");
		exit(1);
	}

	// Create Socket, ETH_ is used because we are listening packets of all kinds.
	if ((sockData = socket(AF_PACKET, SOCK_RAW, htons (ETH_P_ARP))) < 0) {
		perror("Error: MTP socket()");
		exit(1);
	}

	time(&time_advt_beg);
	time(&converge1_beg);
	while (true) {
		time(&time_advt_fin);
		// Send Hello Periodic, only if have atleast One VID in Main VID Table.
		printf("At the top of the white loop");

		if ((double)(difftime(time_advt_fin, time_advt_beg) >= PERIODIC_HELLO_TIME)) {
			memset(interfaceNames, '\0', sizeof(char) * MAX_INTERFACES * MAX_INTERFACES);
			int numberOfInterfaces = getActiveInterfaces(interfaceNames);

			uint8_t *payload = NULL;
			int payloadLen = 0;

			payload = (uint8_t*) calloc (1, MAX_BUFFER_SIZE);

			// send JOIN MSG if there are no VID entries in the Main VID Table.
			if (isMain_VID_Table_Empty()) {
				payloadLen = build_JOIN_MSG_PAYLOAD(payload);
				printf("MTP [JOIN] MESSAGE SENT");
			} else {
				// send if entries already present in Main VID Table.
				payloadLen = build_PERIODIC_MSG_PAYLOAD(payload);
			}

			//send the message (either a JOIN or periodic HELLO)
			if (payloadLen) {
				int i = 0;
				for (; i < numberOfInterfaces; ++i) {
					ctrlSend(interfaceNames[i], payload, payloadLen);
				}
			}
			free(payload);

			memset(deletedVIDs, '\0', sizeof(char) * MAX_VID_LIST * MAX_VID_LIST);

			// check for failures and delete if any VID exceeds periodic hello by (PERIODIC_HELLO_TIME * 3)
			int numberOfDeletions = checkForFailures(deletedVIDs);

			bool hasCPVIDDeletions = checkForFailuresCPVID();

			if ( numberOfDeletions != 0) {

				int i = 0;
				for (; i < numberOfInterfaces; i++) {
					payload = (uint8_t*) calloc (1, MAX_BUFFER_SIZE);

					payloadLen = build_VID_CHANGE_PAYLOAD(payload, interfaceNames[i], deletedVIDs, numberOfDeletions);
					if (payloadLen) {
						ctrlSend(interfaceNames[i], payload, payloadLen);
					}
					free(payload);
				}

				// Also check CPVID Table.
				i = 0;
				for (; i < numberOfDeletions; i++) {
					delete_entry_cpvid_LL(deletedVIDs[i]);
				}


				struct vid_addr_tuple* c1 =  getInstance_vid_tbl_LL();
				if (c1 != NULL) {
					payload = (uint8_t*) calloc (1, MAX_BUFFER_SIZE);
					payloadLen = build_VID_ADVT_PAYLOAD(payload, c1->eth_name);
					if (payloadLen) {
						ctrlSend(c1->eth_name, payload, payloadLen);
					}
					free(payload);
				}

			}

			// print all tables.
			if ((hasCPVIDDeletions == true) || (numberOfDeletions > 0)) {
				print_entries_LL();                     // MAIN VID TABLE
				print_entries_bkp_LL();                 // BKP VID TABLE
				print_entries_cpvid_LL();               // CHILD PVID TABLE
				print_entries_lbcast_LL();              // LOCAL HOST PORTS
			}
			// reset time.
			time(&time_advt_beg);
		}

		socklen_t addr_len = sizeof(src_addr);

		//recvfrom - receive a message from a socket, recvBuffer is where the PDU is stored
		recv_len = recvfrom(sockCtrl, recvBuffer, MAX_BUFFER_SIZE, MSG_DONTWAIT, (struct sockaddr*) &src_addr, &addr_len);
		if (recv_len > 0) {
			char recvOnEtherPort[5];
			// read ethernet header
			eheader = (struct ether_header*)recvBuffer;
			//printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) &eheader->ether_shost));
			//printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)&eheader->ether_dhost));

			if_indextoname(src_addr.sll_ifindex, recvOnEtherPort);

			char ctrlInterface[] = "eth0";

			// ignore frames that are from the control interface.
			if ((strcmp(recvOnEtherPort, ctrlInterface)) == 0) {
				continue;
			} else {
				// This is a MTP frame so, incase this port is in Local host broadcast table remove it.
				delete_entry_lbcast_LL(recvOnEtherPort);
			}

			//switch statement for 14th index of recvBuffer (frame),
			switch ( recvBuffer[14] ) {

				/*
				 *MT_JOIN - this message is sent by a switch that hears  MT_ADVT messages on its ports and desires to join on one of the tree branches the *advertised in the MT_VIDs.
				*/
				case MTP_TYPE_JOIN_MSG:
					{
						printf ("MTP [JOIN] MESSAGE RECIEVED\n");

						uint8_t *payload = NULL;
						int payloadLen = 0;

						payload = (uint8_t*) calloc (1, MAX_BUFFER_SIZE);

						// recvOnEtherPort - Payload destination will same from where Join message has orginated.
						payloadLen = build_VID_ADVT_PAYLOAD(payload, recvOnEtherPort);

						if (payloadLen) {
							ctrlSend(recvOnEtherPort, payload, payloadLen);
						}

						free(payload);
						// Send VID Advt
					}
					break;

				/*
				 *MT_HELLO – this message is a keep-alive indicator and issued periodically on all MTP_ports by a switch running the MTP. A root switch that sends *this message will carry the MT_VID of the root switch. A non-root switch that sends this message will carry all of its MT_VIDs.
				*/
				case MTP_TYPE_PERODIC_MSG:
					{
						// Record MAC ADDRESS, if not already present.
						struct ether_addr src_mac;
						bool retMainVID, retCPVID;

						memcpy(&src_mac, (struct ether_addr *)&eheader->ether_shost, sizeof(struct ether_addr));
						retMainVID = update_hello_time_LL(&src_mac);
						retCPVID = update_hello_time_cpvid_LL(&src_mac);

						if ( (retMainVID == true) || (retCPVID == true) ) {
								printf ("MTP [HELLO KEEP-ALIVE] RECEIVED\n");
						}

						else {
							if (!isRoot) {
								uint8_t *payload = NULL;
								int payloadLen = 0;
								payload = (uint8_t*) calloc (1, MAX_BUFFER_SIZE);
								payloadLen = build_JOIN_MSG_PAYLOAD(payload);
								if (payloadLen) {
									ctrlSend(recvOnEtherPort, payload, payloadLen);
								}
								free(payload);
							}
						}
					}
					break;

					/*
					 *MT_ADVT – A switch which already has an MT_VID, when it receives an MT_NULL message on a port, will move that port to be an MT_port. It will *then send an MT_ADVT message that contains a unique MT_VID that the new switch can use. This MT_VID will be one of its The MT_ADVT message can *also be sent on receiving an MT_JOIN message defined next.
					*/
				case MTP_TYPE_VID_ADVT:
					{
						printf ("[MTP VID INFO RECIEVED: ");

						// Got VID Advt, check relationship, if child add to Child PVID Table.
						// Number of VIDs
						// Message ordering <MSG_TYPE> <OPERATION> <NUMBER_VIDS>  <PATH COST> <VID_ADDR_LEN> <MAIN_TABLE_VID + EGRESS PORT>
						uint8_t operation = (uint8_t) recvBuffer[15];

						if (operation == VID_ADD) {
							uint8_t numberVIDS = (uint8_t) recvBuffer[16];
							//printf ("numberVIDS %u\n", numberVIDS);
							int tracker = 17;
							bool hasAdditions = false;
							while (numberVIDS != 0) {
								uint8_t path_cost = (uint8_t)recvBuffer[tracker];
								printf("Path Cost: %u | ", path_cost);

								// next byte
								tracker = tracker + 1;

								// <VID_ADDR_LEN>
								uint8_t vid_len = recvBuffer[tracker];
								//why is this always coming out to be 5 when implemented?
								printf("VID Address Length: %u | ", vid_len);

								// next byte
								tracker = tracker + 1;

								char vid_addr[vid_len];

								memset(vid_addr, '\0', vid_len);
								strncpy(vid_addr, &recvBuffer[tracker], vid_len);
								printf("VID Address: %s]\n", vid_addr);
								vid_addr[vid_len] = '\0';
								tracker += vid_len;

								int ret = isChild(vid_addr);

								// if VID child ignore, incase part of PVID add to Child PVID table.
								if ( ret == 1) {
									// if this is the first VID in the table and is a child, we have to add into child PVID Table
									if (numberVIDS == (uint8_t) recvBuffer[16]) { // if same first ID
										struct child_pvid_tuple *new_cpvid = (struct child_pvid_tuple*) calloc (1, sizeof(struct child_pvid_tuple));
										// Fill data.
										strncpy(new_cpvid->vid_addr, vid_addr, strlen(vid_addr));
										strncpy(new_cpvid->child_port, recvOnEtherPort, strlen(recvOnEtherPort));
										memcpy(&new_cpvid->mac, (struct ether_addr *)&eheader->ether_shost, sizeof(struct ether_addr));
										new_cpvid->next = NULL;
										new_cpvid->last_updated = time(0);        // last updated time

										// Add into child PVID table, if already there update it if any changes.
										if (add_entry_cpvid_LL(new_cpvid)) {


										} else { // if already there deallocate node memory
											free(new_cpvid);
										}
									}
								} else if ( ret == -1) {
									// Add to Main VID Table, if not a child, make it PVID if there is no better path already in the table.

									// Allocate memory and intialize(calloc).
									struct vid_addr_tuple *new_node = (struct vid_addr_tuple*) calloc (1, sizeof(struct vid_addr_tuple));

									// Fill data.
									strncpy(new_node->vid_addr, vid_addr, strlen(vid_addr));
									strncpy(new_node->eth_name, recvOnEtherPort, strlen(recvOnEtherPort));
									new_node->last_updated = time(0); // current timestamp
									new_node->port_status = PVID_PORT;
									new_node->next = NULL;
									new_node->isNew = true;
									new_node->membership = 0;	 // Intialize with '0', will find outpreference based on cost during add method.
									new_node->path_cost = (uint8_t) path_cost;
									memcpy(&new_node->mac, (struct ether_addr *)&eheader->ether_shost, sizeof(struct ether_addr));

									int mainVIDTracker = add_entry_LL(new_node);
									// Add into VID Table, if addition success, update all other connected peers about the change.
									if (mainVIDTracker > 0) {
										if (mainVIDTracker <= 3) {
											hasAdditions = true;
										}
										// If peer has VID derived from me earlier and has a change now.
										if (numberVIDS == (uint8_t) recvBuffer[16]) { // if same first ID
											// Check PVID used by peer is a derived PVID from me.
											delete_MACentry_cpvid_LL(&new_node->mac);
										}
									}
								}
								printf("First VID Time: %f", (double)(difftime(converge1_fin, converge1_beg)));
								else {
									// Dont do anything, may be a parent vid or duplicate
								}
								numberVIDS--;
							}

							if (hasAdditions) {
								memset(interfaceNames, '\0', sizeof(char) * MAX_INTERFACES * MAX_INTERFACES);
								int numberOfInterfaces = getActiveInterfaces(interfaceNames);

								uint8_t *payload = NULL;
								int payloadLen = 0;

								payload = (uint8_t*) calloc (1, MAX_BUFFER_SIZE);

								int i = 0;
								for (; i < numberOfInterfaces; ++i) {
									// recvOnEtherPort - Payload destination will be same from where Join message has orginated.
									payloadLen = build_VID_ADVT_PAYLOAD(payload, interfaceNames[i]);
									if (payloadLen) {
										ctrlSend(interfaceNames[i], payload, payloadLen);
									}
								}
								free(payload);
							}
						} else if (operation == VID_DEL){
							//printf ("GOT VID_DEL\n");
							// Message ordering <MSG_TYPE> <OPERATION> <NUMBER_VIDS> <VID_ADDR_LEN> <MAIN_TABLE_VID + EGRESS PORT>
							uint8_t numberVIDS = (uint8_t) recvBuffer[16];

							// delete all local entries, get a list and send to others who derive from this VID.
							memset(deletedVIDs, '\0', sizeof(char) * MAX_VID_LIST * MAX_VID_LIST);

							uint8_t numberOfDeletions = numberVIDS;
							bool hasDeletions = false;

							int i = 0;
							int tracker = 17;
							while (i < numberOfDeletions) {
								//<VID_ADDR_LEN>
								uint8_t vid_len = recvBuffer[tracker];

								// next byte, make tracker point to VID_ADDR
								tracker = tracker + 1;

								deletedVIDs[i] = (char*)calloc(vid_len, sizeof(char));
								strncpy(deletedVIDs[i], &recvBuffer[tracker], vid_len);
								recvBuffer[vid_len] = '\0';
								hasDeletions = delete_entry_LL(deletedVIDs[i]);
								delete_entry_cpvid_LL(deletedVIDs[i]);
								tracker += vid_len;
								i++;
							}

							uint8_t *payload;
							int payloadLen;
							// Only if we have deletions we will be advertising it to our connected peers.
							if (hasDeletions) {
								memset(interfaceNames, '\0', sizeof(char) * MAX_INTERFACES * MAX_INTERFACES);
								int numberOfInterfaces = getActiveInterfaces(interfaceNames);

								i = 0;
								for (; i < numberOfInterfaces; i++) {
									payload = (uint8_t*) calloc (1, MAX_BUFFER_SIZE);

									payloadLen = build_VID_CHANGE_PAYLOAD(payload, interfaceNames[i], deletedVIDs, numberOfDeletions);
									if (payloadLen) {
										ctrlSend(interfaceNames[i], payload, payloadLen);
									}
									free(payload);
								}

								payload = (uint8_t*) calloc (1, MAX_BUFFER_SIZE);

								struct vid_addr_tuple* c1 =  getInstance_vid_tbl_LL();
								if (c1 != NULL) {
									payloadLen = build_VID_ADVT_PAYLOAD(payload, c1->eth_name);
									if (payloadLen) {
										ctrlSend(c1->eth_name, payload, payloadLen);
										//printf("Sending %s\n", c1->vid_addr);
									}
									free(payload);
								}
							}

						} else {
							printf("Unknown VID Advertisment\n");
						}
						print_entries_LL();
						print_entries_bkp_LL();
						print_entries_cpvid_LL();
						print_entries_lbcast_LL();
						//added spacing for clarity between updates
						printf("----------------------------------------------------------\n");
					}
					break;

				default:
					printf ("NON-MTP PDU RECIEVED: ");

					printf("Unknown Packet\n");
					break;
			}
		}

		/* Receive data traffic */
		recv_len = recvfrom(sockData, recvBuffer, MAX_BUFFER_SIZE, MSG_DONTWAIT, (struct sockaddr*) &src_addr, &addr_len);
		if (recv_len > 0) {
			char recvOnEtherPort[5];

			if_indextoname(src_addr.sll_ifindex, recvOnEtherPort);
			char ctrlInterface[] = "eth0";

			// ignore frames that are from the control interface.
			if ((strcmp(recvOnEtherPort, ctrlInterface)) == 0) {
				continue;
			}

			// read ethernet header
			eheader = (struct ether_header*)recvBuffer;

			// read ethernet header
			/*printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) &eheader->ether_shost));
			  printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)&eheader->ether_dhost));
			  printf("Message Type: %x\n", ntohs(eheader->ether_type));*/

			// Check if the data frame is a broadcast.
			if (strncmp(ether_ntoa((struct ether_addr *)&eheader->ether_dhost), "ff:ff:ff:ff:ff:ff", 17) == 0) {
				// if the frame is a broadcast frame.
				printf("Received broadcast frame\n");

				// Send it to all host ports, first.
				struct local_bcast_tuple* current =  getInstance_lbcast_LL();

				for (; current != NULL; current = current->next) {
					// port should not be the same from where it received frame.
					if (strcmp(current->eth_name, recvOnEtherPort) != 0) {
						dataSend(current->eth_name, recvBuffer, recv_len);
						printf("Sent to host %s\n", current->eth_name);
					}
				}

				// Next, Send to all ports on Child PVID Table.
				struct child_pvid_tuple* cpt = getInstance_cpvid_LL();

				for (; cpt != NULL; cpt = cpt->next) {
					// port should not be the same from where it received frame.
					if (strcmp(cpt->child_port, recvOnEtherPort) != 0) {
						dataSend(cpt->child_port, recvBuffer, recv_len);
						printf("Sent to child %s\n", cpt->child_port);
					}
				}

				// Next Send it port from where current PVID is acquired, if it is not same as the received port.
				if (!isRoot) {
					struct vid_addr_tuple* vid_t = getInstance_vid_tbl_LL();
					if (strcmp(vid_t->eth_name, recvOnEtherPort) != 0) {
						dataSend(vid_t->eth_name, recvBuffer, recv_len);
						printf("Sent to PVID%s\n", vid_t->eth_name);
					}
				}
				//print_entries_cpvid_LL();
			}

		}
		// check if there are any pending VID Adverts
	} // end of while
}

// get active interfaces on the node.
int getActiveInterfaces(char **ptr ) {
	// find all interfaces on the node.
	int indexLen = 0;

	//structures that describe the network interfaces of the local system
	struct ifaddrs *ifaddr, *ifa;

	/*The getifaddrs() function creates a linked list of structures describing the network interfaces of the local system,
	 *and stores the address of the first item of the list in *ifap.  The list consists of ifaddrs structures
	 */
	if (getifaddrs(&ifaddr) ) {
		perror("Error: getifaddrs Failed\n");
		exit(0);
	}

	// loop through the list, the last part moves the list to the next struct (interface) as long as there still is one (!NULL)
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

		//if the interfaces has no address, continue
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		//family reaches into ifa_addr, which is a pointer to a struct sockaddr variable that describes the address family
		int family;
		family = ifa->ifa_addr->sa_family;

		// populate interface names, if interface is in the AF_INET family, UP, and if ethernet interface doesn't belong to control interface and Loopback interface.
		if (family == AF_INET && (strncmp(ifa->ifa_name, "lo", 2) != 0) && (ifa->ifa_flags & IFF_UP) != 0) {
			char networkIP[NI_MAXHOST];

			//IPv4 AF_INET sockets, grab the IP address from the general ifaddrs struct
			struct sockaddr_in *ipaddr = ((struct sockaddr_in*) ifa->ifa_addr);

			//Converts a numeric address into a text string suitable for presentation (family, source, destination, size)
			inet_ntop(AF_INET, &(ipaddr->sin_addr), networkIP, INET_ADDRSTRLEN);

			//compares first three bytes to determine if its control interface from GENI (172.16.0.0/12)
			if (strncmp(networkIP, CTRL_IP, 3) == 0) {
				// skip, as it is control interface.
				continue;
			}

			//take the argument given to the function, pointer to memory the size of all the interfaces, give it as the dest arg in strncpy.
			ptr[indexLen] = (char*)calloc(strlen(ifa->ifa_name), sizeof(char));
			strncpy(ptr[indexLen], ifa->ifa_name, strlen(ifa->ifa_name));
			indexLen++;
		}
	}
	freeifaddrs(ifaddr);

	return indexLen;
}


void learn_active_interfaces() {
	int numberOfInterfaces;
	char **iNames;

	iNames = (char**) calloc (MAX_INTERFACES*MAX_INTERFACES, sizeof(char));
	memset(iNames, '\0', sizeof(char) * MAX_INTERFACES * MAX_INTERFACES);

	numberOfInterfaces = getActiveInterfaces(iNames);

	int i = 0;
	for (; i < numberOfInterfaces; i++) {
		struct interface_tracker_t *temp = (struct interface_tracker_t*) calloc (1, sizeof(struct interface_tracker_t));
		strncpy (temp->eth_name, iNames[i], strlen(iNames[i]));
		temp->isUP = true;
		temp->next = interfaceTracker;
		interfaceTracker = temp;
	}
}

bool checkInterfaceIsActive(char *str) {
	// find all interfaces on the node.
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) ) {
		perror("Error: getifaddrs Failed\n");
		exit(0);
	}

	// loop through the list
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}
		int family;
		family = ifa->ifa_addr->sa_family;

		if (family == AF_INET && (strncmp(ifa->ifa_name, str, strlen(str)) == 0) && (ifa->ifa_flags & IFF_UP) != 0) {
			freeifaddrs(ifaddr);
			return true;
		}
	}
	freeifaddrs(ifaddr);
	return false;
}
