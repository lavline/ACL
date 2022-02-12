#ifndef __CORE_H_
#define __CORE_H_
#include"tool.h"

#define ENABLE_LOG 0
#define ENABLE_ANALYSE 0

#define LEVEL 4

#define PROTO 1  // if equal to 1 using this att to index
#define PROTO_LAYER 0  //  if this att is enabled, this refers to the layer
#define PROTO_SIZE 4  // protocol layer cell number
#define PROTO_END_CELL 3  // protocol layer cell end id

#define SIP_1 0
#define SIP_1_LAYER 0
#define SIP_SIZE_1 65
#define SIP_EDN_CELL_1 64
#define SIP_WIDTH_1 2  // using to comput index cell id ( x >> *_WIDYH = id )

#define SIP_2 1
#define SIP_2_LAYER 1
#define SIP_SIZE_2 33
#define SIP_EDN_CELL_2 32
#define SIP_WIDTH_2 3

#define SIP_3 0
#define SIP_3_LAYER 1
#define SIP_SIZE_3 33
#define SIP_EDN_CELL_3 32
#define SIP_WIDTH_3 3

#define SIP_4 0
#define SIP_4_LAYER -1
#define SIP_SIZE_4 257
#define SIP_EDN_CELL_4 256
#define SIP_WIDTH_4 0

#define DIP_1 0
#define DIP_1_LAYER 2
#define DIP_SIZE_1 65
#define DIP_EDN_CELL_1 64
#define DIP_WIDTH_1 2

#define DIP_2 1
#define DIP_2_LAYER 2
#define DIP_SIZE_2 257
#define DIP_EDN_CELL_2 256
#define DIP_WIDTH_2 0

#define DIP_3 1
#define DIP_3_LAYER 3
#define DIP_SIZE_3 33
#define DIP_EDN_CELL_3 32
#define DIP_WIDTH_3 3

#define DIP_4 0
#define DIP_4_LAYER 3
#define DIP_SIZE_4 65
#define DIP_EDN_CELL_4 64
#define DIP_WIDTH_4 2

#define SPORT 0
#define SPORT_LAYER -1
#define SPORT_SIZE 65
#define SPORT_END_CELL 64
#define SPORT_WIDTH 10

#define DPORT 0
#define DPORT_LAYER 2
#define DPORT_SIZE 65
#define DPORT_END_CELL 64
#define DPORT_WIDTH 10

#define LAYER_0 4
#define LAYER_1 33
#define LAYER_2 257
#define LAYER_3 33

#define CELL_SIZE 4601025

#define TCP 0x06
#define ICMP 0x01
#define UDP 0x11 

void insert(Cell *c_list, rule *r);
int match(Cell *c_list, message *m);
int match_with_log(Cell* c_list, message* m, int* _cycle, MatchLog* log);

//void check(ACL_rules* r, message* m);
void get_cell_size(Cell* c);
void analyse_log(ACL_rules* data);
double get_memory(Cell* c_list);

#endif // !__CORE_H_
