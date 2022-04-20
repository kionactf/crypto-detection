// A naive implementation of DES for FIPS 46-3

#include <stdio.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;

static const u8 IP[64] = {
58,50,42,34,26,18,10, 2,
60,52,44,36,28,20,12, 4,
62,54,46,38,30,22,14, 6,
64,56,48,40,32,24,16, 8,
57,49,41,33,25,17, 9, 1,
59,51,43,35,27,19,11, 3,
61,53,45,37,29,21,13, 5,
63,55,47,39,31,23,15, 7,
};

static const u8 IPinv[64] = {
40, 8,48,16,56,24,64,32,
39, 7,47,15,55,23,63,31,
38, 6,46,14,54,22,62,30,
37, 5,45,13,53,21,61,29,
36, 4,44,12,52,20,60,28,
35, 3,43,11,51,19,59,27,
34, 2,42,10,50,18,58,26,
33, 1,41, 9,49,17,57,25,
};

static const u8 E[48] = {
32,1 ,2 ,3 ,4 ,5,
4 ,5 ,6 ,7 ,8 ,9,
8 ,9 ,10,11,12,13,
12,13,14,15,16,17,
16,17,18,19,20,21,
20,21,22,23,24,25,
24,25,26,27,28,29,
28,29,30,31,32,1,
};

static const u8 Sbox[8][64] = {
{
14,4 ,13,1 ,2 ,15,11,8 ,3 ,10,6 ,12,5 ,9 ,0 ,7,
0 ,15,7 ,4 ,14,2 ,13,1 ,10,6 ,12,11,9 ,5 ,3 ,8,
4 ,1 ,14,8 ,13,6 ,2 ,11,15,12,9 ,7 ,3 ,10,5 ,0,
15,12,8 ,2 ,4 ,9 ,1 ,7 ,5 ,11,3 ,14,10,0 ,6 ,13,
},
{
15,1 ,8 ,14,6 ,11,3 ,4 ,9 ,7 ,2 ,13,12,0 ,5 ,10,
3 ,13,4 ,7 ,15,2 ,8 ,14,12,0 ,1 ,10,6 ,9 ,11,5,
0 ,14,7 ,11,10,4 ,13,1 ,5 ,8 ,12,6 ,9 ,3 ,2 ,15,
13,8 ,10,1 ,3 ,15,4 ,2 ,11,6 ,7 ,12,0 ,5 ,14,9,
},
{
10,0 ,9 ,14,6 ,3 ,15,5 ,1 ,13,12,7 ,11,4 ,2 ,8,
13,7 ,0 ,9 ,3 ,4 ,6 ,10,2 ,8 ,5 ,14,12,11,15,1,
13,6 ,4 ,9 ,8 ,15,3 ,0 ,11,1 ,2 ,12,5 ,10,14,7,
1 ,10,13,0 ,6 ,9 ,8 ,7 ,4 ,15,14,3 ,11,5 ,2 ,12,
},
{
7 ,13,14,3 ,0 ,6 ,9 ,10,1 ,2 ,8 ,5 ,11,12,4 ,15,
13,8 ,11,5 ,6 ,15,0 ,3 ,4 ,7 ,2 ,12,1 ,10,14,9,
10,6 ,9 ,0 ,12,11,7 ,13,15,1 ,3 ,14,5 ,2 ,8 ,4,
3 ,15,0 ,6 ,10,1 ,13,8 ,9 ,4 ,5 ,11,12,7 ,2 ,14,
},
{
2 ,12,4 ,1 ,7 ,10,11,6 ,8 ,5 ,3 ,15,13,0 ,14,9,
14,11,2 ,12,4 ,7 ,13,1 ,5 ,0 ,15,10,3 ,9 ,8 ,6,
4 ,2 ,1 ,11,10,13,7 ,8 ,15,9 ,12,5 ,6 ,3 ,0 ,14,
11,8 ,12,7 ,1 ,14,2 ,13,6 ,15,0 ,9 ,10,4 ,5 ,3,
},
{
12,1 ,10,15,9 ,2 ,6 ,8 ,0 ,13,3 ,4 ,14,7 ,5 ,11,
10,15,4 ,2 ,7 ,12,9 ,5 ,6 ,1 ,13,14,0 ,11,3 ,8,
9 ,14,15,5 ,2 ,8 ,12,3 ,7 ,0 ,4 ,10,1 ,13,11,6,
4 ,3 ,2 ,12,9 ,5 ,15,10,11,14,1 ,7 ,6 ,0 ,8 ,13,
},
{
4 ,11,2 ,14,15,0 ,8 ,13,3 ,12,9 ,7 ,5 ,10,6 ,1,
13,0 ,11,7 ,4 ,9 ,1 ,10,14,3 ,5 ,12,2 ,15,8 ,6,
1 ,4 ,11,13,12,3 ,7 ,14,10,15,6 ,8 ,0 ,5 ,9 ,2,
6 ,11,13,8 ,1 ,4 ,10,7 ,9 ,5 ,0 ,15,14,2 ,3 ,12,
},
{
13,2 ,8 ,4 ,6 ,15,11,1 ,10,9 ,3 ,14,5 ,0 ,12,7,
1 ,15,13,8 ,10,3 ,7 ,4 ,12,5 ,6 ,11,0 ,14,9 ,2,
7 ,11,4 ,1 ,9 ,12,14,2 ,0 ,6 ,10,13,15,3 ,5 ,8,
2 ,1 ,14,7 ,4 ,10,8 ,13,15,12,9 ,0 ,3 ,5 ,6 ,11,
}
};

static const u8 P[32] = {
16,7 ,20,21,
29,12,28,17,
1 ,15,23,26,
5 ,18,31,10,
2 ,8 ,24,14,
32,27,3 ,9,
19,13,30,6,
22,11,4 ,25,
};

static const u8 PC1[56] = {
57,49,41,33,25,17,9,
1 ,58,50,42,34,26,18,
10,2 ,59,51,43,35,27,
19,11,3 ,60,52,44,36,
63,55,47,39,31,23,15,
7 ,62,54,46,38,30,22,
14,6 ,61,53,45,37,29,
21,13,5 ,28,20,12,4,
};

static const u8 PC2[48] = {
14,17,11,24,1 ,5,
3 ,28,15,6 ,21,10,
23,19,12,4 ,26,8,
16,7 ,27,20,13,2,
41,52,31,37,47,55,
30,40,51,45,33,48,
44,49,39,56,34,53,
46,42,50,36,29,32,
};

static const u8 keyexp_leftshiftnum[16] = {
1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

int permute(u8 out[], u8 input[], u8 trans_table[], unsigned int bitsize) {
    int i;
    int bytepnt;
    int bitpnt;

    for (i=0; i < bitsize; i++) {
	bytepnt = (trans_table[i]-1) / 8;
	bitpnt = 7 - ((trans_table[i]-1) % 8);
        out[i/8] |= ((input[bytepnt]&(1<<bitpnt)) >> bitpnt) << (7 - (i % 8));
    }

    return 0;
}

// input:32bit(8bit 4ary), out:48bit(6bit 8ary)
int expansion(u8 out[], u8 input[]) {
    int i;
    int bytepnt;
    int bitpnt;

    for (i=0; i < 48; i++) {
	bytepnt = (E[i]-1) / 8;
	bitpnt = 7 - ((E[i]-1) % 8);
        out[i/6] |= ((input[bytepnt]&(1<<bitpnt)) >> bitpnt) << (5 - (i % 6));
    }

    return 0;
}

// R:32bit(8bit 4ary), K:48bit(6bit 8ary), out:32bit(8bit 4ary)
int f(u8 out[], u8 R[], u8 K[]) {
    u8 expinput[8];
    u8 Sout[8];
    u8 Pinput[4];
    int i,j,k;

    memset(expinput, 0, 8);
    memset(Sout, 0, 8);
    memset(Pinput, 0, 4);

    expansion(expinput, R);
    for (i=0; i < 8; i++) expinput[i] ^= K[i];

    for (k=0; k < 8; k++) {
        i = ((expinput[k] >> 4) & 0x02) + (expinput[k] & 0x01);
	j = (expinput[k] >> 1) & 0x0f;
	Sout[k] = Sbox[k][16*i+j];
    }

    for (k=0; k < 4; k++) Pinput[k] = (Sout[2*k] << 4) + Sout[2*k+1];

    permute(out, Pinput, (u8*)P, 32);

    return 0;
}

// input:64bit(8bit 8ary), Kexp:16*48bit(6bit 8ary), out:64bit(8bit 8ary)
int des_encrypt_block(u8 out[], u8 input[], u8 Kexp[]) {
    u8 inputstate[8];
    u8 fstate[4];
    u8 outstate[8];
    int i,j;
    u8 tmp;

    memset(inputstate, 0, 8);
    memset(outstate, 0, 8);

    permute(inputstate, input, (u8*)IP, 64);

    for (i=0; i < 16; i++) {
	memset(fstate, 0, 4);
        f(fstate, inputstate+4, Kexp+8*i);
	for (j=0; j < 4; j++) {
	    tmp = inputstate[j];
	    inputstate[j] = inputstate[j+4];
	    inputstate[j+4] = fstate[j]^tmp;
	}
    }
    for (j=0; j < 4; j++) {
        tmp = inputstate[j];
	inputstate[j] = inputstate[j+4];
	inputstate[j+4] = tmp;
    }

    permute(out, inputstate, (u8*)IPinv, 64);

    return 0;
}

int left_rotation_7bit_4ary(u8 out[], u8 input[], u8 rotnum) {
    u32 midnum;

    midnum = ((u32)input[0] << 21) + ((u32)input[1] << 14) + ((u32)input[2] << 7) + ((u32)input[3]);
    midnum = ((midnum << rotnum) & 0xfffffff) | (midnum >> (28-rotnum));
    out[0] = (midnum >> 21) & 0x7f;
    out[1] = (midnum >> 14) & 0x7f;
    out[2] = (midnum >> 7) & 0x7f;
    out[3] = midnum & 0x7f;

    return 0;
}

// KEY:64bit(8bit 8ary), Kexp:16*48bit(6bit 8ary)
int keyschedule(u8 Kexp[], u8 KEY[]) {
    u8 CD[8];
    int bytepnt;
    int bitpnt;
    int i,j;

    memset(CD, 0, 8);

    for (i=0; i < 56; i++) {
	bytepnt = (PC1[i]-1) / 8;
	bitpnt = 7 - ((PC1[i]-1) % 8);
        CD[i/7] |= ((KEY[bytepnt]&(1<<bitpnt)) >> bitpnt) << (6 - (i % 7));
    }

    for (i=0; i < 16; i++) {
        left_rotation_7bit_4ary(CD, CD, keyexp_leftshiftnum[i]);
	left_rotation_7bit_4ary(CD+4, CD+4, keyexp_leftshiftnum[i]);

	for (j=0; j < 48; j++) {
	    bytepnt = (PC2[j]-1) / 7;
	    bitpnt = 6 - ((PC2[j]-1) % 7);
	    Kexp[8*i+j/6] |= ((CD[bytepnt]&(1<<bitpnt)) >> bitpnt) << (5 - (j % 6));
	}
    }
    return 0;
}

#define KEYSIZE 8
#define INPUTSIZE 8
#define OUTPUTSIZE 8

int main() {
    u8 cipherKey[KEYSIZE];
    u8 Kexp[16*8];
    u8 pt[INPUTSIZE];
    u8 ct[OUTPUTSIZE];
    int i;

    memset(Kexp, 0, 16*8);
    memset(ct, 0, OUTPUTSIZE);

    for (i=0; i < KEYSIZE; i++) cipherKey[i] = (u8)i;
    for (i=0; i < INPUTSIZE; i++) pt[i] = (u8)i;

    keyschedule(Kexp, cipherKey);
    des_encrypt_block(ct, pt, Kexp);

    for (i=0; i < OUTPUTSIZE; i++) {
        printf("%02x ", (unsigned char)ct[i]);
    }
    printf("\n");

    return 0;
}
