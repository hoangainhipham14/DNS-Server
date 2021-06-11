#ifndef DNS_SVR_H
#define DNS_SVR_H

int recv_query(int *sockfd, int *newsockfd, uint16_t **query);
void send_res(uint16_t **response, int len, int *newsockfd);

#endif
