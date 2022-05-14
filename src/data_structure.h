#ifndef __DATA_STRUCTURE_H_
#define __DATA_STRUCTURE_H_
#include<stdio.h>

typedef struct rule {
	int PRI;  //priority
	unsigned char protocol[2];  // [0] : mask [1] : protocol
	unsigned char source_mask;
	unsigned char destination_mask;
	unsigned char source_ip[4];
	unsigned char destination_ip[4];
	unsigned short source_port[2];
	unsigned short destination_port[2];
}rule;

typedef struct ACL_rules
{
	unsigned int size;
	unsigned int capacity;
	rule* list;
}ACL_rules;

typedef struct data
{
	int PRI;  //priority
	unsigned char protocol[2];
	unsigned char source_mask;
	unsigned char destination_mask;
	unsigned char source_ip[4];
	unsigned char destination_ip[4];
	unsigned short source_port[2];
	unsigned short destination_port[2];
}data;

typedef struct Cell
{
	unsigned int size;
	unsigned int capacity;
	data* list;
}Cell;

typedef struct message
{
	unsigned int protocol;
	unsigned char source_ip[4];
	unsigned char destination_ip[4];
	unsigned short source_port;
	unsigned short destination_port;
}message;

typedef struct ACL_messages
{
	unsigned int size;
	unsigned int capacity;
	message* list;
}ACL_messages;

typedef struct LogInCell
{
	int id;
	int layer[5];
	int size;
	int rules;
	int ele;
	int match;
	int HPRI;
}LogInCell;

typedef struct MatchLog
{
	int rules;
	int ele;
	LogInCell* list;
}MatchLog;

typedef struct IntegerList
{
	uint32_t size;
	uint32_t capacity;
	int* list;
}IntegerList;

#endif //__DATA_STRUCTURE_H_