#ifndef __CORE_H_
#define __CORE_H_
#include"tool.h"

#define IP_SIZE 17
#define IP_EDN_CELL 16
#define IP_WIDTH 4
#define PORT_SIZE 65
#define PORT_END_CELL 64
#define PORT_WIDTH 10
#define CELL_SIZE 649539

void insert(Cell *c_list, rule *r);
int match(Cell *c_list, message *m);

void check(ACL_rules* r, message* m);
void get_cell_size(Cell* c);
void analyse_log(ACL_rules* data);

#endif // !__CORE_H_
