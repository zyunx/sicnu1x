#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define USERNAME	"1sx201@mp"
#define PASSWORD	"6543210"


struct eap_ether_frame
{
	uint8_t version;
	uint8_t type;
	uint16_t length;
}__attribute__((packed));

char *EAP_FRAME_TYPE[] = {
	"EAP-Packet(0)",
	"EAPOL-Start(1)",
	"EAPOL-Logoff(2)",
	"EAPOL-Key(3)",
	"EAPOL-Encapsulated-ASF-Alert(4)"
};
struct eaphdr
{
	uint8_t code;
	uint8_t id;
	uint16_t length;
	uint8_t type;
} __attribute__((packed));

static const char *EAP_CODE_NAME[] =
{
	"Invalid(0)",
	"Request(1)",
	"Response(2)",
	"Success(3)",
	"Failure(4)"
};

#define EAP_C_REQUEST 1
#define EAP_C_RESPONSE 2
#define EAP_C_SUCCESS 3
#define EAP_C_FAILURE 4

#define EAP_T_IDENTITY		1
#define EAP_T_NOTIFICATION	2
#define EAP_T_NAK			3
#define EAP_T_MD5_CHALLENGE	4
#define EAP_T_OTP			5	/* One-Time Password */
#define EAP_T_GTC			6	/* Generic Token Card */


#include "md5.h"

void print_md5(uint8_t *m)
{
	int i;
	for (i = 0; i < 16; i++)
	{
		printf("%02x", *m);
		m++;
	}
	printf("\n");
}
void print_md5_res(uint8_t id, char *password,
		uint8_t *md5_req, uint8_t md5_req_len)
{
	uint8_t md[16];
	uint16_t dlen = 1 + strlen(password) + md5_req_len;
	uint8_t *data = malloc(dlen);
	assert(data != NULL);

	memcpy(data, &id, 1);
	memcpy(data + 1, password, strlen(password));
	memcpy(data + 1 + strlen(password),
			md5_req, md5_req_len);
	
	md5(md, data, dlen);
//	md5(md, data, dlen);

	free(data);

	print_md5(md);	

}

void print_msg(char *m, int len)
{
	int i = 0;
	while (i < len)
	{
		printf("%c", *m);
		m++;
		i++;
	}
	printf("\n");
}


int main()
{
	int s; /* socket descriptor */
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	assert(s != -1);

	void *buffer = (void *)malloc(ETH_FRAME_LEN);
	int length = 0;
	struct ethhdr *eth;
	struct eap_ether_frame *eap_frame;
	struct eaphdr *eap;
	uint16_t type;
	char *msg;

	uint8_t *md5_size;
	uint8_t *md5_value;

	while(1)
	{
		printf(".");		
		length = recvfrom(s, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
		assert(length != -1);
		eth = (struct ethhdr *)buffer;
		if (ntohs(eth->h_proto) == ETH_P_PAE) {
			printf("======================\n");

			printf("Ethernet Length: %04x " \
					"Type: %04x " \
					"Dest: %02x:%02x:%02x:%02x:%02x:%02x " \
					"Src: %02x:%02x:%02x:%02x:%02x:%02x\n", 
					length,
					ntohs(eth->h_proto),
					eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
					eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
					eth->h_source[0], eth->h_source[1], eth->h_source[2],
					eth->h_source[3], eth->h_source[4], eth->h_source[5]);
			
			eap_frame = (struct eap_ether_frame*) (eth+1);
			printf("EAP Ether Frame Version: %2x Type:%s Length: %4x\n",
					eap_frame->version,
					EAP_FRAME_TYPE[eap_frame->type],
					ntohs(eap_frame->length));

			if (eap_frame->length != 0)
			{
				eap = (struct eaphdr*) (eap_frame + 1);
				printf("EAP Packet Code:%02x, Id: %2x, Length: %4x\n",
						eap->code,
						eap->id,
						ntohs(eap->length));
			}

			switch (eap->type)
			{
				case EAP_T_IDENTITY:
					msg = (char *)(eap+1);
					print_msg(msg, ntohs(eap->length));
					break;
				//case EAP_T_NOTIFICATION:
				//	print_msg((char *)(eap+1), ntohs(eap->length));
				//	break;
				case EAP_T_MD5_CHALLENGE:
					md5_size = (uint8_t *)(eap+1);
					printf("%02x\n", *md5_size);
					md5_value = md5_size + 1;
					print_md5(md5_value);
					print_md5_res(eap->id, PASSWORD, md5_value, *md5_size);

					break;
				default:
					break;
			}

		}
/*
		if (eth->h_proto < ETH_FRAME_LEN)
		{
			printf("IEEE 802.3 FRMAE !!!!\n");
			type = (uint16_t)(*(((char *)buffer) + 20));
			if (ntohs(type) == ETH_P_PAE)
			{
				printf("ETH_P_PAE\n");
			}
		}*/
	}
}
