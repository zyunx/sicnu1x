#include "crc_ether.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

uint8_t CRC32[] = {0x04, 0xC1, 0x1D, 0xB7};
uint8_t CRC32R[] = {0xED, 0xB8, 0x83, 0x20};

static uint8_t shift_register[4]; /* current window for dividing */
static int p8, p1; /* pointer to the next(p8 * 8 + 1) not processed bit */
static int is_end;

static uint8_t *data_appended;
static int32_t data_len;

static int reverse_u8(uint8_t *u8)
{
	uint8_t r;
	uint8_t B;

	B = *u8;
	r = 0;
	r |= (B & 0x1) << 7;
	r |= (B & 0x2) << 5;
	r |= (B & 0x4) << 3;
	r |= (B & 0x8) << 1;
	r |= (B & 0x10) >> 1;
	r |= (B & 0x20) >> 3;
	r |= (B & 0x40) >> 5;
	r |= (B & 0x80) >> 7;
	(*u8) = r;
	return 0;
}


/* init context for crc32 ethernet. */
static void crc32_ether_init(uint8_t *data, uint32_t len)
{
	int i;
	uint8_t t;
	
	/* hold data */
	data_appended = (uint8_t *) malloc(len + 4);
	assert(data_appended != NULL);
	memcpy(data_appended, data, len);
	/* reserse data */
	for (i = 0; i < len; i++)
	{
		reverse_u8(&data_appended[i]);
	}
	/* pad */
	data_appended[len] = 0;
	data_appended[len+1] = 0;
	data_appended[len+2] = 0;
	data_appended[len+3] = 0;
	data_len = len + 4;
	/* XOR 0xFFFFFFFF */
	data_appended[0] ^= 0xFF;
	data_appended[1] ^= 0xFF;
	data_appended[2] ^= 0xFF;
	data_appended[3] ^= 0xFF;

	/* init shift_register */
	memset(shift_register, 0, 4);
	is_end = 0;
	p8=0;
	p1=0;
}

static void crc32_ether_fini()
{
	/* xored */
	shift_register[0] ^= 0xFF;
	shift_register[1] ^= 0xFF;
	shift_register[2] ^= 0xFF;
	shift_register[3] ^= 0xFF;

	/* reverse */
	reverse_u8(&shift_register[0]);
	reverse_u8(&shift_register[1]);
	reverse_u8(&shift_register[2]);
	reverse_u8(&shift_register[3]);

	/* free data */
	free(data_appended);
	data_appended = NULL;
	data_len = 0;
}


/* the most significant 1 bit's position 
 * from most to least, counted begining at 1 */
static int most_sig_pos(uint8_t n)
{
	if (n == 0)
	{
		return 0;
	} else {
		int i = 1;
		while (((uint8_t)(n << 1)) > n)
		{
		//	printf("%d\n", n);
			n <<= 1;
			i++;
		}
		return i;
	}
}

static void shift_one_bit_to_reg()
{
	if (p8 < data_len && p1 < 8)
	{
		shift_register[0] = (shift_register[0] << 1) | 
			((shift_register[1] & 0x80) ? 1 : 0);
		shift_register[1] = (shift_register[1] << 1) | 
			((shift_register[2] & 0x80) ? 1 : 0);
		shift_register[2] = (shift_register[2] << 1) | 
			((shift_register[3] & 0x80) ? 1 : 0);
		shift_register[3] = (shift_register[3] << 1) | 
			(((data_appended[p8] << p1) & 0x80) ? 1 : 0);
printf(".");
		p1++;
		p8 += p1 / 8;
		p1 %= 8;
	} else {
		is_end = 1;
	}
}

static void shift_data_to_reg()
{
	int sb;	/* bits need be shifted */

	while (shift_register[0] == 0)
	{
		if (p1 == 0)
		{
			if (p8 < data_len)
			{
				shift_register[0] = shift_register[1];
				shift_register[1] = shift_register[2];
				shift_register[2] = shift_register[3];
				shift_register[3] = data_appended[p8];
				p8++;
			} else {
				is_end = 1;
				return;
			}
		} else {
			if (p8 < data_len - 1)
			{
				shift_register[0] = shift_register[1];
				shift_register[1] = shift_register[2];
				shift_register[2] = shift_register[3];
				shift_register[3] = (data_appended[p8] << p1) | 
					((data_appended[p8+1] >> (8-p1))); 
				p8++;

			} else if (p8 == data_len - 1) {
				shift_register[0] = shift_register[1] >> (8-p1);
				shift_register[1] = (shift_register[1] << (8-p1)) | 
					(shift_register[2] >> (8-p1));
				shift_register[2] = (shift_register[2] << (8-p1)) |
					(shift_register[3] >> (8-p1));
				shift_register[3] = (shift_register[3] << (8-p1)) | 
					(data_appended[p8] & ((1 << p1) - 1));
				p8++;

				is_end = 1;
				return;
	
			} else {
				/* imposiible */
				assert(0);
			}
		}
	}

	/* shift 1 bit */
	sb = most_sig_pos(shift_register[0]);
	
}

static void divide_and_remainder()
{
	shift_register[0] ^= CRC32[0];
	shift_register[1] ^= CRC32[1];
	shift_register[2] ^= CRC32[2];
	shift_register[3] ^= CRC32[3];

}

static int print_crc32(uint8_t crc[4])
{
	printf("%02x%02x%02x%02x\n", crc[0], crc[1], crc[2], crc[3]);
	return 0;
}
static int poly_divide()
{
	/*
	 * While is not end:
	 *		1. Shift the rest bits to the shift register.
	 * 		2. Divide the shift register and put
	 * 			remainder to the shift register.
	 */

//print_crc32(data_appendd);
	while(!is_end)
	{
		while (!is_end && !(0x80 & shift_register[0])) shift_one_bit_to_reg();
print_crc32(shift_register);	
		if (is_end) 
		{
			break;
		}
		shift_one_bit_to_reg();
		divide_and_remainder();
	}

	return 0;
}

int crc_ether(uint8_t crc[4], uint8_t *data, uint32_t len)
{
	crc32_ether_init(data, len);

	poly_divide();
	
	crc32_ether_fini();

	crc[0] = shift_register[0];
	crc[1] = shift_register[1];
	crc[2] = shift_register[2];
	crc[3] = shift_register[3];
	
	return 0;
}

/*
int main(int argc, char **argv)
{
	uint8_t crc[4];
	//uint8_t a[] = {0x40};
	//crc32_ether(crc, a, 1);
	crc32_ether(crc, argv[1], strlen(argv[1]));
	print_crc32(crc);

	//uint8_t b = 0xE5;
	//reverse_u8(&b);
	//printf("%2x\n", b);
	return 0;
}
*/
