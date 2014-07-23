#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "md5.h"

#define USERNAME	"1sx201@mp"
#define PASSWORD	"6543210"


struct eap_ether_frame
{
	uint8_t version;
	uint8_t type;
	uint16_t length;
}__attribute__((packed));

#define EAP_ETHER_T_PACKET	0
#define EAP_ETHER_T_START	1

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


uint8_t *cons_eap_start(uint8_t buf[ETH_FRAME_LEN], uint16_t *load_len)
{
	struct eap_ether_frame *p = (struct eap_ether_frame *)buf;
	p->version = 1;
	p->type = EAP_ETHER_T_START;
	p->length = htons(0);

	*load_len = sizeof(struct eap_ether_frame);
	
	return buf;
}

uint8_t *cons_eap_ident_res(uint8_t buf[ETH_FRAME_LEN],
		uint16_t *load_len,
		uint8_t id,
		char *ident)
{
	uint16_t pkg_len = strlen(ident) + sizeof(struct eaphdr);

	struct eap_ether_frame *p = (struct eap_ether_frame *)buf;
	p->version = 1;
	p->type = EAP_ETHER_T_PACKET;
	p->length = htons(pkg_len);

	struct eaphdr * ph = (struct eaphdr *) (p + 1);
	ph->code = EAP_C_RESPONSE;
	ph->id = id;
	ph->length = htons(pkg_len);
	ph->type = EAP_T_IDENTITY;

	char *pi = (char *) (ph + 1);
	memcpy(pi, ident, strlen(ident));

	*load_len = pkg_len + sizeof(struct eap_ether_frame);

	return buf;
}

uint8_t *cons_eap_md5_res(uint8_t buf[ETH_FRAME_LEN],
		uint16_t *load_len,
		uint8_t id,
		uint8_t *md5_req, uint16_t md5_req_len,
		char *password)
{
	uint16_t pkg_len = 17 + sizeof(struct eaphdr);

	struct eap_ether_frame *p = (struct eap_ether_frame *) buf;
	p->version = 1;
	p->type = EAP_ETHER_T_PACKET;
	p->length = htons(pkg_len);

	struct eaphdr * ph = (struct eaphdr *) (p + 1);
	ph->code = EAP_C_RESPONSE;
	ph->id = id;
	ph->length = htons(pkg_len);
	ph->type = EAP_T_MD5_CHALLENGE;

	uint8_t *pi = (uint8_t *) (ph + 1);
	uint8_t md[16];
	uint16_t dlen = 1 + strlen(password) + md5_req_len;
	uint8_t *data = malloc(dlen);
	memcpy(data, &id, 1);
	memcpy(data + 1, password, strlen(password));
	memcpy(data + 1 + strlen(password),
			md5_req, md5_req_len);
	md5(md, data, dlen);
	free(data);

	*pi = 16;
	memcpy(pi + 1, md, 16);

	*load_len = pkg_len + sizeof(struct eap_ether_frame);

	return buf;

}


uint8_t dest_mac[] = {
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x03
};

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

int die(char *s)
{
	printf("sincu1x: %s\n", s);
	exit(1);
}

int main()
{
	char *if_name = "eth0";
	int ifindex = -1;
	
	// open socket
	int s; /* socket descriptor */
	s = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_PAE));
	assert(s != -1);

	// get the interface index
	struct ifreq ifr;
	memcpy(ifr.ifr_name, if_name, strlen(if_name)+1);
	if (ioctl(s, SIOCGIFINDEX, &ifr) == -1)
	{
		printf("Can't get interface index.\n");
		exit(1);
	}
	ifindex = ifr.ifr_ifindex;

	// construct destination address
	struct sockaddr_ll addr;
	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifindex;
	addr.sll_halen = ETH_ALEN;
	addr.sll_protocol = htons(ETH_P_PAE);
	memcpy(addr.sll_addr, dest_mac, ETH_ALEN);

	void *buffer = (void *)malloc(ETH_FRAME_LEN);
	uint16_t load_len;
	uint16_t length = 0;
	struct eap_ether_frame *eap_frame;
	struct eaphdr *eap;
	uint16_t type;
	char *msg;

	uint8_t *md5_size;
	uint8_t *md5_value;

	cons_eap_start(buffer, &load_len);
	if (-1 == sendto(s, buffer, load_len, 0, (struct sockaddr*)&addr, sizeof(addr)))
	{
		die("Send PAE-Start failed.");
	}

	printf("Having sent PAE-Start.\n");

	while(1)
	{
		printf(".");		
		length = recvfrom(s, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
		assert(length != -1);
		printf("Receive a EAP packet.\n");
			
		eap_frame = (struct eap_ether_frame*) (buffer);

		if (eap_frame->type == EAP_ETHER_T_PACKET)
		{
			printf("EAP Ether Frame Version: %2x Type:%s Length: %4x\n",
				eap_frame->version,
				EAP_FRAME_TYPE[eap_frame->type],
				ntohs(eap_frame->length));

			if (ntohs(eap_frame->length) != 0)
			{
				eap = (struct eaphdr*) (eap_frame + 1);
				printf("EAP Packet Code: %s, Id: %2x, " \
						"Length: %4x\n",
						eap->code <= 4 ? EAP_CODE_NAME[eap->code]: "(null)",
						eap->id,
						ntohs(eap->length));

				if (eap->code == EAP_C_REQUEST)
				{
					switch(eap->type)
					{
						case EAP_T_IDENTITY:
							printf("Process Identity packet\n");
							cons_eap_ident_res(buffer, &load_len,
									eap->id, USERNAME);
							if(-1 == sendto(s, buffer, load_len, 0,
									(struct sockaddr*)&addr, sizeof(addr)))
							{
								die("Send Identity response failed.\n");
							}
							else
							{
								printf("Send Identity response success.\n");
							}
							break;
						case EAP_T_MD5_CHALLENGE:
							printf("Process MD5 Challenge packet\n");
							md5_value = ((uint8_t *) (eap + 1)) + 1;
							md5_size = ((uint8_t *) (eap + 1));
							cons_eap_md5_res(buffer, &load_len,
									eap->id,
									md5_value, *md5_size,
									PASSWORD);
							if (-1 == sendto(s, buffer, load_len,
										0,
										(struct sockaddr *) &addr,
										sizeof(addr)))
							{
								printf("Send MD5 Response Fails.\n");
							}
							else
							{
								printf("Send MD5 Response Succeed.\n");
							}
							break;
						default:
							break;
					}
				}
			}

		
		}
		
	}

	close(s);
}
