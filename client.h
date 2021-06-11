#ifndef CLIENT_H
#define CLIENT_H

void send_query(char *ip, char *port, uint16_t **query, int len, int *sockfd_upstream);
int recv_res(int *sockfd_upstream, uint16_t **response);
#endif
