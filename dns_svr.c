#define _POSIX_C_SOURCE 200112L
#define MAX_MSG 256
#define HEADER_LEN 12
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "dns_svr.h"
#include "client.h"
#include "phase1.h"
#include "error_handling.h"

int main(int argc, char *argv[]) 
{
    FILE *fp;
    fp = fopen("dns_svr.log", "w");

    if (argc < 3)
    {
        fprintf(stderr, "ERROR, incorrect number of arguments provided.\n\
            Usage: ./dns_svr <server-ip> <server-port>\n");
        exit(EXIT_FAILURE);
    }

    // program stops when Ctrl + C
    signal(SIGINT, SIG_DFL);

    while (1) {
        int *sockfd = (int *)malloc(sizeof(int) * 1);
        int *newsockfd = (int *)malloc(sizeof(int) * 1);
        int *sockfd_upstream = (int *)malloc(sizeof(int) * 1);
        int len_req, len_res;
        bool AAAA_req;

        uint16_t **query = (uint16_t **)malloc(sizeof(uint16_t *) * 1);
        query[0] = malloc(sizeof(uint16_t) * 400);

        // get query from dig
        len_req = recv_query(sockfd, newsockfd, query);

        // parse query
        AAAA_req = parse_msg(query, fp, len_req);

        // if query is AAAA
        if (AAAA_req) {

            // forward to upstream server
            send_query(argv[1], argv[2], query, len_req, sockfd_upstream);

            // get response from upstream server
            uint16_t **response = (uint16_t **)malloc(sizeof(uint16_t *) * 1);
            response[0] = malloc(sizeof(uint16_t) * MAX_MSG);
            len_res = recv_res(sockfd_upstream, response);

            // parse response
            parse_msg(response, fp, len_res);

            // send response back to client
            send_res(response, len_res, newsockfd);

            // free memory
            free(response[0]);
            free(response);
            response = NULL;

        } else {

            // if not AAAA request, handle error
            err_handle(query);

            // send rcode = 4 
            send_res(query, HEADER_LEN, newsockfd);
        }

        // free memory
        close(*sockfd);
        close(*newsockfd);
        close(*sockfd_upstream);
        free(sockfd);
        free(newsockfd);
        free(sockfd_upstream);
        free(query[0]);
        free(query);
        query = NULL;
   
    }

    return 0;
}

int recv_query(int *sockfd, int *newsockfd, uint16_t **query)
{
	int n, re;
    struct sockaddr_in serv_addr;

    serv_addr.sin_family = AF_INET;    
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(8053);

	// Create socket
	*sockfd = socket(serv_addr.sin_family, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

    //Reuse port if possible
    re = 1;
    if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0)
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind address to the socket
    if (bind(*sockfd,  (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // Listen on socket
    if (listen(*sockfd, 5) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // Accept a connection 
    int addrlen = sizeof(serv_addr);
    *newsockfd =
        accept(*sockfd, (struct sockaddr *)&serv_addr, (socklen_t*)&addrlen);
    if (*newsockfd < 0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    int i = 0;
    int len = 0;
    int bytes_read = 0;

    // read query byte by byte
    uint8_t *input = malloc(sizeof(uint8_t) * MAX_MSG);
    while (1) {
        n = read(*newsockfd, &(input[i]), 1);
        bytes_read += n;

        if (bytes_read >= 2) {
            char *msg_len = (char *)malloc(sizeof(char) * 5);
            assert(msg_len != NULL);
            sprintf(msg_len, "%02x%02x", input[0], input[1]);
            len = hex_deci(&msg_len, 16);
            free(msg_len);
        }

        // stops when bytes_read = length of query
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
        query[0][j] = input[i] << 8 | input[i + 1];
        i += 2;
        j++;
    }

    return len;
}

void send_res(uint16_t **response, int len, int *newsockfd) {

    // convert to network order byte
    for (int i = 0; i < (len + 2) / 2; i++) {
        response[0][i] = htons(response[0][i]);
    }

	// Send message to server
	int n = write(*newsockfd, response[0], len + 2);
	if (n < 0) {
		perror("write");
		exit(EXIT_FAILURE);
	}
}
