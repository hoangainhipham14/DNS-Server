#include <stdint.h>
#include <stdio.h>

#define HEADER_LEN 12

void err_handle(uint16_t **buffer) {

    // set everything else 0
    buffer[0][2] = 0;

    // set QR = 1
    buffer[0][2] = buffer[0][2] | (1 << 15);

    // set Rcode = 4
    buffer[0][2] = buffer[0][2] | 4;

    // set RD = 1 
    buffer[0][2] = buffer[0][2] | (11 << 7);
    
    // set number of query = 0
    buffer[0][3] = 0;

    // set length of message = length of header
    buffer[0][0] = HEADER_LEN;

    // set number of numer of response = 0
    buffer[0][4] = 0;

    // set number of authority record = 0
    buffer[0][5] = 0;

    // set number of additional record = 0
    buffer[0][6] = 0;
}
