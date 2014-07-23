#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Copy from wikipedia
//Note: All variables are unsigned 32 bit and wrap modulo 2^32 when calculating

//s specifies the per-round shift amounts
static int shift[] = {
	// 1..15
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	// 16..31
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	//32..47
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	// 48..63
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

//Use binary integer part of the sines of integers (Radians) as constants:
//for i from 0 to 63
//    K[i] := floor(abs(sin(i + 1)) × (2 pow 32))
//end for
static int K[] = {
	//0..3
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	//4..7
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	//8..11
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	//12..15
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	//16..19
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	//20..23
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	//24..27
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 
	//28..31
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	//32..35
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	//36..39
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	//40..43
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	//44..47
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	//48..51
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	//52..55
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	//56..59
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	//60..63
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};



#define left_rotate32(a,r) ((a) << (r) | (a) >> (32-(r)))

int md5(uint8_t md[16], uint8_t* data, uint64_t len)
{
	uint8_t *data_appended = NULL;
	uint64_t data_len;
	uint32_t M[16];

	uint32_t i, j, g;
	uint64_t bits_len;
	uint32_t A, B, C, D, F;
	uint32_t dTemp;

	//Initialize variables:
	uint32_t a0 = 0x67452301;  //A
	uint32_t b0 = 0xefcdab89;  //B
	uint32_t c0 = 0x98badcfe;  //C
	uint32_t d0 = 0x10325476;  //D


	int ap = 64 - (len + 1) % 64 + 1;
	//if (data_appended != NULL) free(data_appended);
	data_appended = (uint8_t *) malloc(len + ap);
	data_len = len + ap;
	memcpy(data_appended, data, len);

	//Pre-processing: adding a single 1 bit
	data_appended[len] = 0x80;
	//Notice: the input bytes are considered as bits strings,
	//where the first bit is the most significant bit of the byte.
	

	//Pre-processing: padding with zeros
	//append "0" bit until message length in bits ≡ 448 (mod 512)
	for (i = len + 1; i < data_len - 8; i++)
	{
		data_appended[i] = 0;
	}

	//append original length in bits mod (2 pow 64) to message
	bits_len = len * 8;
	data_appended[data_len - 1] = bits_len >> 56;
	data_appended[data_len - 2] = bits_len >> 48;
	data_appended[data_len - 3] = bits_len >> 40;
	data_appended[data_len - 4] = bits_len >> 32;
	data_appended[data_len - 5] = bits_len >> 24;
	data_appended[data_len - 6] = bits_len >> 16;
	data_appended[data_len - 7] = bits_len >> 8;
	data_appended[data_len - 8] = bits_len;
//printf("%02x\n", data_appended[data_len-1]);

	//Process the message in successive 512-bit chunks:
	//for each 512-bit chunk of message
	for (i = 0; i < data_len; i += 64)
	{
		// process the message in successive 512-bit chunks
		for (j = 0; j < 16; j++)
		{
			M[j] = *((uint32_t *)(&data_appended[i+j*4]));
		}

		// Initialize hash value for this chank
		A = a0;
		B = b0;
		C = c0;
		D = d0;

		for (j = 0; j < 64; j++)
		{
			if (j >= 0 && j <= 15)
			{
				F = (B & C) | (~B & D);
				g = j;
			} else if (j >= 16 && j <= 31)
			{
				F = (D & B) | (~D & C);
				g = (5 * j + 1) % 16;
			} else if (j >= 32 && j <= 47)
			{
				F = B ^ C ^ D;
				g = (3 * j + 5) % 16;
			} else if (j >= 48 && j <= 63)
			{
				F = C ^ (B | ~D);
				g = (7 * j) % 16;
			}

			dTemp = D;
			D = C;
			C = B;
			B = B + left_rotate32(A + F + K[j] + M[g], shift[j]);
			A = dTemp;
		}

		a0 += A;
		b0 += B;
		c0 += C;
		d0 += D;
	}

	*((uint32_t *)&md[0]) = a0;
	*((uint32_t *)&md[4]) = b0;
	*((uint32_t *)&md[8]) = c0;
	*((uint32_t *)&md[12]) = d0;


	free(data_appended);
	data_appended = NULL;

	return 0;
}

/*
int main(int argc, char **argv)
{
	uint8_t md[16];
	int i;

	md5(md, argv[1], strlen(argv[1]));
	md5(md, argv[1], strlen(argv[1]));
	for (i = 0; i < 16; i++)
	{
		printf("%02x", md[i]);
	}
	printf("\n");
}
*/
