#ifndef __READ_H_
#define __READ_H_
#include"tool.h"
#include "data_structure.h"

int read_rules(const char* file_name, ACL_rules* rules);
int read_messages(const char* file_name, ACL_messages* messages, IntegerList* check_list);

int read_contest_rule(const char* file_name, ACL_rules* rules);
int read_contest_message(const char* file_name, ACL_messages* messages);

#endif // !__READ_H_
