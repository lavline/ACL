#ifndef __TOOL_H_
#define __TOOL_H_
#include<string.h>
#include<malloc.h>
#include <stdint.h>
#include <time.h>
#include"data_structure.h"


void add_rule(ACL_rules* rules, rule* r);
void add_data(Cell* c, data* d);
void add_message(ACL_messages* messages, message* m);
void integer_list_push_back(IntegerList* a, int* b);

double get_nano_time(struct timespec* a, struct timespec* b);

uint64_t GetCPUCycle();

#endif // !__C_VECTOR_H_
