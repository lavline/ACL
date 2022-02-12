#include"core.h"
#include"read.h"

int main() {

	if (!check_configure())return -1;

	ACL_rules datasets = { 0,0,0 };
	ACL_messages message_sets = { 0,0,0 };
	Cell* index;
	index = (Cell*)calloc(CELL_SIZE, sizeof(Cell));
	read_rules("/home/lzhy/ACL_dataset/acl2_256k.txt", &datasets);
	read_messages("/home/lzhy/ACL_dataset/acl2_256k_trace.txt", &message_sets);

	for (int i = 0; i < datasets.size; i++) {
		insert(index, datasets.list + i);
	}

#if ENABLE_ANALYSE
	//analyse_log(&datasets);
	get_cell_size(index);
	printf("%f MB\n", get_memory(index));
#endif
	
	int res = 0;
	int cycle = 0;
	MatchLog match_log;
	match_log.list = (LogInCell*)malloc(16 * sizeof(LogInCell));
	FILE* res_fp = NULL;
	res_fp = fopen("match_cycle.txt", "w");

	for (int i = 0; i < message_sets.size; i += 100) {
		res = match_with_log(index, message_sets.list + i, &cycle, &match_log);
#if ENABLE_LOG
		fprintf(res_fp, "message %d match_rule %d cycle %f check_rules %d check_element %d\n", i + 100, res, cycle / 100.0, match_log.rules, match_log.ele);
		for (int j = 0; j < 16; j++)
			fprintf(res_fp, "\tid %d %d %d %d %d size %d CRul %d CEle %d match %d\n", 
				match_log.list[j].id, match_log.list[j].layer[0], match_log.list[j].layer[1], match_log.list[j].layer[2], match_log.list[j].layer[3],
				match_log.list[j].size, match_log.list[j].rules, match_log.list[j].ele, match_log.list[j].match);
#else
		fprintf(res_fp, "message %d match_rule %d cycle %f\n", i + 100, res, cycle / 100.0);
#endif
	}

	fclose(res_fp);
	
	for (int i = 0; i < CELL_SIZE; i++)free(index[i].list);  // free cell list
	free(index);  // free cell
	free(message_sets.list); // free message list
	free(datasets.list);  // free dataset list
	free(match_log.list);  // free log list
	return 0;
}

