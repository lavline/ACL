#ifndef __CORE_H_
#define __CORE_H_
#include"tool.h"

#define LEVEL 4

#define PROTO_SIZE 4
#define PROTO_END_CELL 3

#define IP_SIZE_1 33
#define IP_EDN_CELL_1 32
#define IP_WIDTH_1 3

#define IP_SIZE_2 257
#define IP_EDN_CELL_2 256
#define IP_WIDTH_2 0

#define PORT_SIZE 65
#define PORT_END_CELL 64
#define PORT_WIDTH 10

#define CELL_SIZE 2205060

#define TCP 0x06
#define ICMP 0x01
#define UDP 0x11 

void insert(Cell *c_list, rule *r);
int match(Cell *c_list, message *m);

void check(ACL_rules* r, message* m);
void get_cell_size(Cell* c);
void analyse_log(ACL_rules* data);

#endif // !__CORE_H_
