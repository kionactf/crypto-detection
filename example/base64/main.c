#include <stdio.h>
#include <string.h>
#include "base64.h"


#define INPUTSIZE 13
#define OUTPUTSIZE 20
int main() {
    char pt[INPUTSIZE+1];
    char ct[OUTPUTSIZE+1];
    int i;

    memset(ct, 0, OUTPUTSIZE+1);

    for (i=0; i < INPUTSIZE; i++) pt[i] = (char)i;

    base64_encode(pt, INPUTSIZE, ct, OUTPUTSIZE);

    printf("%s\n", ct);

    return 0;
}
