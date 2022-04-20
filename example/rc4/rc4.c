// naive reimplementation of rc4. refer: http://cypherpunks.venona.com/archive/1994/09/msg00304.html

#include <stdio.h>
#include <string.h>

#define u8 unsigned char

// state:8bit 256 ary, keydata:8bit (keydatalength) ary
int prepare_key(u8 state[], u8 keydata[], unsigned int keydatalength) {
    int i,j;
    u8 tmp;

    for (i=0; i < 256; i++)
        state[i] = i;

    j = 0;
    for (i=0; i < 256; i++) {
        j = (keydata[i % keydatalength] + state[i] + j) % 256;
	tmp = state[j];
	state[j] = state[i];
	state[i] = tmp;
    }
    return 0;
}

int rc4_encrypt(u8 output[], u8 input[], unsigned int len, u8 state[]) {
    int cnt,i,j;
    u8 tmp;

    j = 0;
    for (cnt=0; cnt < len; cnt++) {
	i = (cnt + 1) % 256;
        j = (state[i] + j) % 256;
	tmp = state[j];
	state[j] = state[i];
	state[i] = tmp;

	output[cnt] = input[cnt] ^ state[(state[i] + state[j]) % 256];
    }
    return 0;
}

#define KEYSIZE 16
#define INPUTSIZE 32
#define OUTPUTSIZE 32

int main() {
    u8 key[KEYSIZE];
    u8 input[INPUTSIZE];
    u8 output[OUTPUTSIZE];
    u8 state[256];
    int i;

    memset(key, 0, KEYSIZE);
    memset(input, 0, INPUTSIZE);
    memset(output, 0, OUTPUTSIZE);

    for (i=0; i < KEYSIZE; i++) key[i] = i;
    for (i=0; i < INPUTSIZE; i++) input[i] = i;

    prepare_key(state, key, KEYSIZE);
    rc4_encrypt(output, input, INPUTSIZE, state);

    for (int i=0; i < OUTPUTSIZE; i++)
        printf("%02x ", output[i]);
    printf("\n");

    return 0;
}
