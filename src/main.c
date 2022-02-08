#include"core.h"
#include"read.h"

int main() {
	ACL_rules datasets = { 0,0,0 };
	ACL_messages message_sets = { 0,0,0 };
	Cell* index;
	index = (Cell*)calloc(CELL_SIZE, sizeof(Cell));
	read_rules("/home/lzhy/ACL_dataset/fw4_256k.txt", &datasets);
	read_messages("/home/lzhy/ACL_dataset/fw4_256k_trace.txt", &message_sets);

	//for (int i = 0; i < datasets.size; i++) {
	//	insert(index, datasets.list + i);
	//}

	analyse_log(&datasets);
	//get_cell_size(index);
	//printf("%f MB\n", get_memory(index));
	/*
	int res = 0;
	int cycle = 0;
	int *match_log;
	match_log = (int*)malloc(2 * sizeof(int));
	FILE* res_fp = NULL;
	res_fp = fopen("match_cycle.txt", "w");

	for (int i = 0; i < message_sets.size; i += 100) {
		match_log[0] = match_log[1] = 0;
		res = match_with_log(index, message_sets.list + i, &cycle, match_log);
		fprintf(res_fp, "message %d match_rule %d cycle %f check_rules %f check_element %f\n", i + 100, res, cycle / 100.0, match_log[0] / 100.0, match_log[1] / 100.0);
	}

	fclose(res_fp);
	*/
	for (int i = 0; i < CELL_SIZE; i++)free(index[i].list);
	free(index);  // free cell
	free(message_sets.list); // free message
	free(datasets.list);  // free dataset
	//free(match_log);  // free log
	return 0;
}

