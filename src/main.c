#include <stdlib.h>
#include"core.h"
#include"read.h"

int main() {
	if (ENABLE_ANALYSE)printf("Enable Analyse\n");
	if (ENABLE_LOG)printf("Enable Log\n");
	if (ENABLE_ANALYSE || ENABLE_LOG)printf("\n");
	if (!check_configure())return -1;
	//printf("%ld\n", sizeof(int*));
	
	ACL_rules datasets = { 0,0,0 };
	ACL_messages message_sets = { 0,0,0 };
	Cell* index;
	index = (Cell*)calloc(CELL_SIZE, sizeof(Cell));

	//read_rules("/home/lzhy/ACL_dataset/acl2_256k.txt", &datasets);
	//read_messages("/home/lzhy/ACL_dataset/acl2_256k_trace.txt", &message_sets);
	read_rules("/root/ACL_dataset/acl3_256k.txt", &datasets);
	read_messages("/root/ACL_dataset/acl3_256k_trace-1.txt", &message_sets);

	// get rand insert sequence
	int* index_array = (int*)malloc(datasets.size * sizeof(int));
	int* check_index = (int*)calloc(datasets.size, sizeof(int));
	for (int i = 0; i < datasets.size; i++) {
		int temp;
		while (check_index[temp = (rand() % datasets.size)]);
		index_array[i] = temp;
		check_index[temp] = 1;
	}
	for (int i = 0; i < datasets.size; i++) {
		if (!check_index[i]) {
			printf("gen rand index sequence error!\n");
			return -1;
		}
	}
	free(check_index);

	// insert
	uint64_t insert_cycle = GetCPUCycle();
	for (int i = 0; i < datasets.size; i++) {
		insert(index, datasets.list + index_array[i]);
		//insert(index, datasets.list + i);
	}
	insert_cycle = GetCPUCycle() - insert_cycle;
	printf("avg insert cycle: %f\n", (double)insert_cycle / datasets.size);
	free(index_array);

	//check_indexCell(index + 4934205);

#if ENABLE_ANALYSE
	//analyse_log(&datasets);
	get_cell_size(index);
	printf("%f MB\n", get_memory(index));
#endif
	int res = 0;
	int cycle = 0;

	MatchLog match_log;
#if ENABLE_LOG
	match_log.list = (LogInCell*)malloc((1 << LEVEL) * sizeof(LogInCell));
#endif
	FILE* res_fp = NULL;
	res_fp = fopen("match_cycle.txt", "w");

	// match
	for (int i = 0; i < message_sets.size; i++) {
		res = match_with_log(index, message_sets.list + i, &cycle, &match_log);
#if ENABLE_LOG
		fprintf(res_fp, "message %d match_rule %d cycle %d check_rules %d check_element %d\n", i + RECORD_STEP, res, cycle, match_log.rules, match_log.ele);
		for (int j = 0; j < (1 << LEVEL); j++) {
			fprintf(res_fp, "\tid %d ", match_log.list[j].id);
			for (int k = 0; k < LEVEL; k++) fprintf(res_fp, "%d ", match_log.list[j].layer[k]);
			fprintf(res_fp, "size %d CRul %d CEle %d HPRI %d match %d\n",
				match_log.list[j].size, match_log.list[j].rules, match_log.list[j].ele, match_log.list[j].HPRI, match_log.list[j].match);
		}
#else
		fprintf(res_fp, "message %d match_rule %d cycle %d\n", i, res, cycle);
#endif
	}

	fclose(res_fp);
	//printf("average_match_cycle %f\n", average / message_sets.size);

	for (int i = 0; i < CELL_SIZE; i++)free(index[i].list);  // free cell list
	free(index);  // free cell
	free(message_sets.list); // free message list
	free(datasets.list);  // free dataset list
#if ENABLE_LOG
	free(match_log.list);  // free log list
#endif
	printf("program complete\n");
	return 0;
}

