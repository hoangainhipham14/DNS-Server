#ifndef PHASE1_H
#define PHASE1_H

#include <stdbool.h>

bool parse_msg(uint16_t **buffer, FILE *fp, int len);
void print_log(char *dname, char *ip, int QR, bool AAAA_type, FILE *fp, int nres);
int parse_req(uint16_t **buffer, int k, char **info, int nbits, int *shift);
int parse_dname(uint16_t **buffer, int k, char *dname, int *shift);
void check_null(uint16_t *info);
int hex_deci(char **info, int nbits);
int format_ip(uint16_t **buffer, uint8_t **ip, int k, int nbits, char *ip_add, int *shift);
void free_mem(char **info);
#endif
