#include <stdlib.h>
#include"core.h"
#include"read.h"

int main() {
	FILE* config_file = NULL;
	config_file = fopen("config", "r");
	if (config_file == NULL) {
		fprintf(stderr, "error - can not open config file\n");
		return -1;
	}
	char rule_file[100] = { 0 };
	char trace_file[100] = { 0 };
	fscanf(config_file, "%s\n%s", rule_file, trace_file);
	fclose(config_file);

	if (ENABLE_ANALYSE)printf("Enable Analyse\n");
	if (ENABLE_LOG)printf("Enable Log\n");
	if (ENABLE_ANALYSE || ENABLE_LOG)printf("\n");
	if (!check_configure())return -1;
	//printf("%ld\n", sizeof(int*));
	
	ACL_rules datasets = { 0,0,0 };
	ACL_messages message_sets = { 0,0,0 };

	printf("read rules frome %s ...\n", rule_file);
	//if (!read_rules(rule_file, &datasets))return -1;
	if (!read_contest_rule(rule_file, &datasets))return -1;
	printf("read rules complete\n");
	printf("read trace frome %s ...\n", trace_file);
	//if (!read_messages(trace_file, &message_sets))return -1;
	if (!read_contest_message(trace_file, &message_sets))return -1;
	printf("read trace complete\n\n");

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
	printf("insert start...\n");
	Cell* index;
	index = (Cell*)calloc(CELL_SIZE, sizeof(Cell));
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
	double total_cycle = 0;
	MatchLog match_log = { 0 };

	printf("match start...\n");
#if ENABLE_LOG
	match_log.list = (LogInCell*)malloc((1 << LEVEL) * sizeof(LogInCell));
#endif
	FILE* res_fp = NULL;
	res_fp = fopen("match_cycle.txt", "w");

	// match
	struct timespec t1, t2;
	double total_time = 0;
	for (int i = 0; i < message_sets.size; i++) {
		clock_gettime(CLOCK_REALTIME, &t1);
		res = match_with_log(index, message_sets.list + i, &cycle, &match_log);
		clock_gettime(CLOCK_REALTIME, &t2);
		total_time += get_nano_time(&t1, &t2);
		total_cycle += cycle;
#if ENABLE_LOG
		fprintf(res_fp, "message %d match_rule %d cycle %d check_rules %d check_element %d\n", i, res, cycle, match_log.rules, match_log.ele);
#if LOG_LEVEL == 2
		for (int j = 0; j < (1 << LEVEL); j++) {
			fprintf(res_fp, "\tid %d ", match_log.list[j].id);
			for (int k = 0; k < LEVEL; k++) fprintf(res_fp, "%d ", match_log.list[j].layer[k]);
			fprintf(res_fp, "size %d CRul %d CEle %d HPRI %d match %d\n",
				match_log.list[j].size, match_log.list[j].rules, match_log.list[j].ele, match_log.list[j].HPRI, match_log.list[j].match);
		}
#endif
#else
		fprintf(res_fp, "message %d match_rule %d cycle %d\n", i, res, cycle);
#endif
	}

	fclose(res_fp);
	printf("average_match_cycle %f\n", total_cycle / (double)message_sets.size);
	printf("average_match_time %f\n\n", total_time / (double)message_sets.size / 1000.0);

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

