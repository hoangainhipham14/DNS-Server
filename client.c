#define _POSIX_C_SOURCE 200112L
#define MAX_MSG 256

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <strings.h>
#include <assert.h>
#include <sys/socket.h>

#include "client.h"
#include "phase1.h"

void send_query(char *ip, char *port, uint16_t **query, int len, int *sockfd_upstream) 
{
	struct sockaddr_in serv_addr;

 	if ((*sockfd_upstream = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        exit(EXIT_FAILURE);
    }
   
    serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(atoi(port));
	serv_addr.sin_addr.s_addr = inet_addr(ip);
       
    // Convert IPv4 from text to binary form
    if(inet_pton(AF_INET, ip, &(serv_addr.sin_addr.s_addr))<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        exit(EXIT_FAILURE);
    }
	
    // Connect upstream server
    if (connect(*sockfd_upstream, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("%d ", errno);
        printf("\nConnection Failed \n");
        exit(EXIT_FAILURE);
    }

    // convert to network byte order
    for (int i = 0; i < (len + 2) / 2 + 1; i++) {
        query[0][i] = htons(query[0][i]);
    }

	// Send message to server
	int n = write(*sockfd_upstream, query[0], len + 2);
	if (n < 0) {
		perror("write");
		exit(EXIT_FAILURE);
	}

}

int recv_res(int *sockfd_upstream, uint16_t **response) {

	int i = 0;
    int len = 0;
    int bytes_read = 0;
    int n;

    // receive response from server byte by byte
    uint8_t *input = malloc(sizeof(uint8_t) * MAX_MSG);
    while (1) {
        n = read(*sockfd_upstream, &(input[i]), 1);
        bytes_read += n;

        if (bytes_read >= 2) {
            char *msg_len = (char *)malloc(sizeof(char) * 5);
            assert(msg_len != NULL);
            sprintf(msg_len, "%02x%02x", input[0], input[1]);
            len = hex_deci(&msg_len, 16);
            free(msg_len);
        }

        // stops when bytes_read = length of response
        if (bytes_read == len + 2) {
            break;
        }

        if (n < 0) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        i++;
    }
    
    i = 0;
    int j = 0;

    // store in uint16_t for easier parsing
    while (i < len) {
        response[0][j] = input[i] << 8 | input[i + 1];
        i += 2;
        j++;
    }

	return len;
}
