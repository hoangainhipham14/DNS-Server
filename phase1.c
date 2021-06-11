#define _POSIX_C_SOURCE 200112L
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>
#include <assert.h>
#include <math.h>

#define MAX_BYTES 1000
#define MAX_LABELS 4
#define MAX_LEN 40
#define BITS_PER_BYTE 8
#define BITS_PER_HEX 4
#define HEX_PER_BYTE 2

#include "phase1.h"

bool parse_msg(uint16_t **buffer, FILE *fp, int len)
{   
    int QR = buffer[0][2] >> 15;

    // get number of response
    char *str = malloc(sizeof(char) * 5);
    sprintf(str, "%04x", buffer[0][4]);
    int nres = hex_deci(&str, 16);
    free(str);

  
    // if need to bit shift
    int shift = 1;
    int i;

    // get domain name
    char *dname = (char *)calloc(MAX_BYTES, sizeof(char));
    assert(dname != NULL);
    i = parse_dname(buffer, 7, dname, &shift);

    // get qtype
    int nbits = 16;
    char **qtype = (char **)malloc(sizeof(char *) * 1);
    assert(qtype != NULL);
    qtype[0] = malloc(sizeof(char) * (nbits / BITS_PER_HEX + 1));
    assert(qtype[0] != NULL);
    i = parse_req(buffer, i, qtype, nbits, &shift);

    // check if AAAA query
    char *AAAA = (char *)malloc(sizeof(char) * 7);
    sprintf(AAAA, "%04x", (uint16_t)0x001c);

    bool AAAA_type = true;
    if (memcmp(qtype[0], AAAA, 5) != 0)
    {
        AAAA_type = false;
        free(AAAA);
    } 
    free_mem(qtype);

    // get class
    char **class = (char **)malloc(sizeof(char *) * 1);
    assert(class != NULL);
    class[0] = malloc(sizeof(char) * (nbits / BITS_PER_HEX + 1));
    assert(class[0] != NULL);
    i = parse_req(buffer, i, class, nbits, &shift);
    free_mem(class);

    char *ip_add;
    char **name, **ttl, **rd;
    uint8_t **ip;

    // if it's response
    if (QR == 1)
    {
        if (nres > 0) {

            // get name
            nbits = 16;
            name = (char **)malloc(sizeof(char *) * 1);
            assert(name != NULL);
            name[0] = malloc(sizeof(char) * (nbits / BITS_PER_HEX + 1));
            assert(name[0] != NULL);
            i = parse_req(buffer, i, name, nbits, &shift);

            // get response qtype
            char **qtype = (char **)malloc(sizeof(char *) * 1);
            assert(qtype != NULL);
            qtype[0] = malloc(sizeof(char) * (nbits / BITS_PER_HEX + 1));
            assert(qtype[0] != NULL);
            i = parse_req(buffer, i, qtype, nbits, &shift);

            // check if AAAA response
            char *AAAA = (char *)malloc(sizeof(char) * 7);
            sprintf(AAAA, "%04x", (uint16_t)0x001c);

            if (memcmp(qtype[0], AAAA, 5) != 0)
            {
                AAAA_type = false;
                free(AAAA);
            } 
            free_mem(qtype);

            // get class
            char **class = (char **)malloc(sizeof(char *) * 1);
            assert(class != NULL);
            class[0] = malloc(sizeof(char) * (nbits / BITS_PER_HEX + 1));
            assert(class[0] != NULL);
            i = parse_req(buffer, i, class, nbits, &shift);
            free_mem(class);

            // get ttl
            nbits = 32;
            ttl = (char **)malloc(sizeof(char *) * 1);
            assert(ttl != NULL);
            ttl[0] = malloc(sizeof(char) * (nbits / BITS_PER_HEX + 1));
            assert(ttl[0] != NULL);
            i = parse_req(buffer, i, ttl, nbits, &shift);

            // if response is AAAA
            if (AAAA_type) {
                nbits = 16;
                rd = (char **)malloc(sizeof(char *) * 1);
                assert(rd != NULL);
                rd[0] = malloc(sizeof(char) * (nbits / BITS_PER_HEX + 1));
                assert(rd[0] != NULL);
                i = parse_req(buffer, i, rd, nbits, &shift);
                int nbytes = hex_deci(rd, 16);

                if (nbytes == 16)
                {   
                    // get ip address
                    ip = (uint8_t **)malloc(sizeof(uint8_t *) * 1);
                    assert(ip != NULL);
                    ip_add = (char *)malloc(sizeof(char) * 45);
                    assert(ip_add != NULL);
                    i = format_ip(buffer, ip, i, nbits, ip_add, &shift);
                }
            }
           
        }
    }

    // log query/response
    print_log(dname, ip_add, QR, AAAA_type, fp, nres);

    // free memory
    if (QR == 1 && nres > 0) {
        if (AAAA_type) {
            free(ip[0]);
            free(ip);
            free(ip_add);
            free_mem(rd);
            ip = NULL;
            rd = NULL;
            ip_add = NULL;
        }
        free_mem(ttl);
        free_mem(name);
        ttl = NULL;
        name = NULL;
    }
    
    free(dname);
    qtype = NULL;
    dname = NULL;
    class = NULL;

    return AAAA_type;
}

int format_ip(uint16_t **buffer, uint8_t **ip, int k, int nbytes, char *ip_add, int *shift)
{
    int count_bits = 0;
    uint8_t hi, lo;
    int i = 0;
    int nbits = nbytes * 8;
    ip[0] = malloc(sizeof(uint8_t) * 16);

    while (count_bits < nbits)
    {
        if (*shift == 1)
        {   
            hi = buffer[0][k] >> 8;
            ip[0][i] = hi;
            *shift = 0;
            i++;
        }
        else
        {
            lo = buffer[0][k] >> 0;
            ip[0][i] = lo;
            *shift = 1;
            i++;
            k++;
        }
        count_bits += 8;
    }
    inet_ntop(AF_INET6, ip[0], ip_add, 45);
    return k;
}

// conver hexadecimal to decimal
int hex_deci(char **info, int nbits)
{
    int m = 0;
    int total = 0;

    for (int j = nbits / BITS_PER_HEX - 1; j >= 0; j--)
    {
        switch (info[0][j])
        {
        case '0':
            total += (0 * pow(16, m));
            m += 1;
            break;
        case '1':
            total += (1 * pow(16, m));
            m += 1;
            break;
        case '2':
            total += (2 * pow(16, m));
            m += 1;
            break;
        case '3':
            total += (3 * pow(16, m));
            m += 1;
            break;
        case '4':
            total += (4 * pow(16, m));
            m += 1;
            break;
        case '5':
            total += (5 * pow(16, m));
            m += 1;
            break;
        case '6':
            total += (6 * pow(16, m));
            m += 1;
            break;
        case '7':
            total += (7 * pow(16, m));
            m += 1;
            break;
        case '8':
            total += (8 * pow(16, m));
            m += 1;
            break;
        case '9':
            total += (9 * pow(16, m));
            m += 1;
            break;
        case 'a':
            total += (10 * pow(16, m));
            m += 1;
            break;
        case 'b':
            total += (11 * pow(16, m));
            m += 1;
            break;
        case 'c':
            total += (12 * pow(16, m));
            m += 1;
            break;
        case 'd':
            total += (13 * pow(16, m));
            m += 1;
            break;
        case 'e':
            total += (14 * pow(16, m));
            m += 1;
            break;
        case 'f':
            total += (15 * pow(16, m));
            m += 1;
            break;
        default:
            printf("\n Invalid hexa digit %c ", info[0][j]);
            return 0;
        }
    }
    return total;
}

int parse_dname(uint16_t **buffer, int k, char *dname, int *shift)
{
    int len = 0;
    bool is_len = true;
    int count = 0;
    int i = 0;
    uint8_t lo, hi;
    int alloc = MAX_BYTES;
    char *str;

    // if it's null terminate 
    while (len != 0 || i == 0)
    {
        if (i == alloc)
        {
            alloc += MAX_BYTES;
            dname = realloc(dname, (alloc + 1));
        }

        // if it's not length of label, construct label
        while (!is_len)
        {
            if (*shift == 1)
            {
                hi = buffer[0][k] >> 8;
                dname[i] = hi;
                *shift = 0;
            }
            else
            {
                lo = buffer[0][k] >> 0;
                dname[i] = lo;
                *shift = 1;
                k++;
            }

            i += 1;
            count++;

            if (count == len)
            {
                dname[i] = '.';
                i++;
                count = 0;
                is_len = true;
            }
        }

        if (is_len)
        {
            str = malloc(sizeof(char) * 3);
            
            // get length of labels
            if (*shift == 1)
            {
                hi = buffer[0][k] >> 8;
                sprintf(str, "%02x", hi);
                *shift = 0;
            }
            else
            {
                lo = buffer[0][k] >> 0;
                sprintf(str, "%02x", lo);
                *shift = 1;
                k++;
            }

            len = hex_deci(&str, 8);
            printf("len %d ", len);
            free(str);

            // if not null terminate & not length, construct dname
            if (*shift == 1 && len != 0)
            {
                hi = buffer[0][k] >> 8;
                dname[i] = hi;
                *shift = 0;
                i++;
                count++;
            }

            // if not null terminate & not length, construct dname
            if (*shift == 0 && len != 0)
            {
                lo = buffer[0][k] >> 0;
                dname[i] = lo;
                *shift = 1;
                count++;
                i++;
                k++;
            }   

            if (count == len)
            {
                dname[i] = '.';
                i++;
                count = 0;
                is_len = true;
            }
            else
            {
                is_len = false;
            }
        }
    }
    dname[i - 2] = '\0';
    return (k);
}

int parse_req(uint16_t **buffer, int k, char **info, int nbits, int *shift)
{
    uint8_t lo, hi;
    int count_bits = 0;
    int len = 0;

    while (count_bits < nbits)
    {   
        char *str = (char *)malloc(sizeof(char) * 5);
        if (*shift == 1)
        {
            hi = buffer[0][k] >> 8;
            if (len == 0) {
                sprintf(str, "%02x", hi);
                strcpy(info[0], str);
            } else {
                sprintf(str, "%02x", hi);
                strcat(info[0], str);
            }
            *shift = 0;
        }
        else
        {
            lo = buffer[0][k] >> 0;
            if (len == 0) {
                sprintf(str, "%02x", lo);
                strcpy(info[0], str);
            } else {
                sprintf(str, "%02x", lo);
                strcat(info[0], str);
            }
            *shift = 1;
            k++;
        }
        free(str);
        count_bits += 8;
        len += 2;
        info[0][len] = '\0';
    }
    return k;
}

void print_log(char *dname, char *ip, int QR, bool AAAA_type, FILE *fp, int nres)
{
    time_t rawtime;
    struct tm *info;
    char buffer[80];

    time(&rawtime);

    info = localtime(&rawtime);

    strftime(buffer, 80, "%FT%T%z", info);

    if (QR == 0)
    {
        fprintf(fp, "%s requested %s\n", buffer, dname);
        fflush(fp);
        if (!AAAA_type)
        {
            fprintf(fp, "%s unimplemented request\n", buffer);
            fflush(fp);
        }
    }
    
    if (AAAA_type && QR == 1 && nres > 0)
    {
        fprintf(fp, "%s %s is at %s\n", buffer, dname, ip);
        fflush(fp);
    }
}

void free_mem(char **info) {
    free(info[0]);
    free(info);
}
