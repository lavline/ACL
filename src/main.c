#include"core.h"
#include"read.h"

int main() {
	ACL_rules datasets = { 0,0,0 };
	ACL_messages message_sets = { 0,0,0 };
	Cell* index;
	index = (Cell*)calloc(CELL_SIZE, sizeof(Cell));
	read_rules("acl1_256k.txt", &datasets);
	read_messages("acl1_256k_trace.txt", &message_sets);
	
	
	for (int i = 0; i < datasets.size; i++)
		insert(index, datasets.list + i);
	/*
	printf("%f MB\n", get_memory(index));
	analyse_log(&datasets);
	get_cell_size(index);
	*/
	
	int res = 0;
	int cycle = 0;
	FILE* res_fp = NULL;
	res_fp = fopen("match_cycle.txt", "w");
	
	for (int i = 0; i < message_sets.size; i++) {
		res = match_with_log(index, message_sets.list + i, &cycle);
		//printf("message %d match_rule %d cycle %d\n", i, res, cycle);
		fprintf(res_fp, "message %d match_rule %d cycle %d\n", i, res, cycle);
	}
	
	fclose(res_fp);
	
	for (int i = 0; i < CELL_SIZE; i++)free(index[i].list);
	free(index);
	free(message_sets.list);
	free(datasets.list);
	return 0;
}

