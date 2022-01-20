#ifndef __CORE_H_
#define __CORE_H_
#include"tool.h"

void insert(Cell *c_list, rule *r);
int match(Cell *c_list, message *m);
void check(ACL_rules* r, message* m);

#endif // !__CORE_H_
