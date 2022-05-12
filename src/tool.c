#include"tool.h"

void add_rule(ACL_rules* rules, rule* r) {
	if (rules->size < rules->capacity) {
		memcpy(rules->list + rules->size, r, sizeof(rule));
		rules->size++;
	}
	else {
		rules->capacity += 8;
		rule* p = (rule*)realloc(rules->list, rules->capacity * sizeof(rule));
		if (p == NULL) {
			fprintf(stderr, "Error - unable to allocate required memory\n");
		}
		else {
			rules->list = p;
			memcpy(rules->list + rules->size, r, sizeof(rule));
			rules->size++;
		}
	}
}

// 按优先级有序插入
void add_data(Cell* c, data* d)
{
	// 扩容
	if (c->capacity <= c->size) {
		c->capacity += 8;
		data* p = (data*)realloc(c->list, c->capacity * sizeof(data));
		if (p == NULL) {
			fprintf(stderr, "Error - unable to allocate required memory\n");
		}
		else {
			c->list = p;
		}
	}
	// 按优先级有序插入
	if (c->list != NULL) { 
		int i = 0;
		for (i; i < c->size; i++) {
			if (c->list[i].PRI > d->PRI)break;
		}
		if (i < c->size) {
			memmove(c->list + i + 1, c->list + i, (c->size - i) * sizeof(data));
		}
		memcpy(c->list + i, d, sizeof(data));
		c->size++;
	}
}

void add_message(ACL_messages* messages, message* m) 
{
	if (messages->size < messages->capacity) {
		memcpy(messages->list + messages->size, m, sizeof(message));
		messages->size++;
	}
	else {
		messages->capacity += 8;
		message* p = (message*)realloc(messages->list, messages->capacity * sizeof(message));
		if (p == NULL) {
			fprintf(stderr, "Error - unable to allocate required memory\n");
		}
		else {
			messages->list = p;
			memcpy(messages->list + messages->size, m, sizeof(message));
			messages->size++;
		}
	}
}

void add_cell(CellList* _list, Cell* _c) {
	if (_list->size < _list->capacity) {
		memcpy(_list->list + _list->size, _c, sizeof(Cell));
		++_list->size;
	}
	else {
		_list->capacity += 8;
		Cell* p = (Cell*)realloc(_list->list, _list->capacity * sizeof(Cell));
		if (p == NULL) {
			fprintf(stderr, "Error - unable to allocate required memory\n");
		}
		else {
			_list->list = p;
			memcpy(_list->list + _list->size, _c, sizeof(Cell));
			++_list->size;
		}
	}
}

double get_nano_time(struct timespec* a, struct timespec* b)
{
	return (b->tv_sec - a->tv_sec) * 1000000000 + b->tv_nsec - a->tv_nsec;
}

inline uint64_t GetCPUCycle()
{
#ifdef __x86_64__
	unsigned int lo, hi;
	__asm__ __volatile__("lfence" : : : "memory");
	__asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
	return ((uint64_t)hi << 32) | lo;
#elif __aarch64__
	uint64_t v = 0;
	asm volatile("isb" : : : "memory");
	asm volatile("mrs %0, cntvct_el0" : "=r"(v));
	return v;
#else
	printf("unknown arch\n");
	return 0;
#endif
}