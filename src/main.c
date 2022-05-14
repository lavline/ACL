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
	IntegerList check_message_set = { 0,0,0 };

	printf("read rules frome %s ...\n", rule_file);
	if (!read_rules(rule_file, &datasets))return -1;
	//if (!read_contest_rule(rule_file, &datasets))return -1;
	printf("read rules complete\n");
	printf("read trace frome %s ...\n", trace_file);
	if (!read_messages(trace_file, &message_sets, &check_message_set))return -1;
	//if (!read_contest_message(trace_file, &message_sets))return -1;
	printf("read trace complete\n\n");

	//analyse_data(&datasets);

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

	/*{
		FILE* cell_fp = NULL;
		cell_fp = fopen("index.txt", "w");
		int cell_num = 0;
		for (int i = 0; i < CELL_SIZE; i++) {
			if (index[i].size > 0) {
				++cell_num;
				fprintf(cell_fp, "cell_id=%d, cell_size=%d\n", i, index[i].size);
				data* _d = index[i].list;
				for (int j = 0; j < index[i].size; j++)fprintf(cell_fp, "\tsip=%u.%u.%u.%u/%u,dip=%u.%u.%u.%u/%u,sport=%u:%u,dport=%u:%u,proto=%u,index=%u\n",
					_d[j].source_ip[3], _d[j].source_ip[2], _d[j].source_ip[1], _d[j].source_ip[0], _d[j].source_mask,
					_d[j].destination_ip[3], _d[j].destination_ip[2], _d[j].destination_ip[1], _d[j].destination_ip[0], _d[j].destination_mask,
					_d[j].source_port[0], _d[j].source_port[1], _d[j].destination_port[0], _d[j].destination_port[1], (unsigned int)(_d[j].protocol[1]), _d[j].PRI);
			}
		}
		fclose(cell_fp);
		printf("%d\n", cell_num);
	}*/

	//check_indexCell(index + 4934205);
	printf("%f MB\n", get_memory(index));

#if ENABLE_ANALYSE
	//analyse_log(&datasets);
	get_cell_size(index);
	
#endif
	int res = 0;
	int cycle = 0;
	double total_cycle = 0;
	MatchLog match_log = { 0 };

	// warm up
	for (int x = 0; x < 10; ++x) {
		for (int i = 0; i < message_sets.size; i++) {
			match_with_log(index, message_sets.list + i, &cycle, &match_log);
}
	}

	printf("match start...\n");
#if ENABLE_LOG
	match_log.list = (LogInCell*)malloc((1 << LEVEL) * sizeof(LogInCell));
#endif
	FILE* res_fp = NULL;
	res_fp = fopen("match_cycle.txt", "w");

	// match
	struct timespec t1, t2;
	double total_time = 0;
	double temp_time = 0;
	for (int i = 0; i < message_sets.size; i++) {
		/*if (i == 166) {
			printf("breakpoint\n");
		}*/
		clock_gettime(CLOCK_REALTIME, &t1);
		res = match_with_log(index, message_sets.list + i, &cycle, &match_log);
		clock_gettime(CLOCK_REALTIME, &t2);
		temp_time = get_nano_time(&t1, &t2);
		total_time += temp_time;
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
		if (res != check_message_set.list[i]) {
			if (!check_correct(datasets.list + res, message_sets.list + i)) {
				fprintf(stderr, "match result %d is uncorrect! true is %d, but match %d.", i, check_message_set.list[i], res);
				goto END;
			}
		}
		fprintf(res_fp, "message %d match_rule %d cycle %d time %lf\n", i, res, cycle, temp_time);
#endif
	}

	printf("average_match_cycle %f\n", total_cycle / (double)message_sets.size);
	printf("average_match_time %f\n\n", total_time / (double)message_sets.size / 1000.0);

	END:
	fclose(res_fp);
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

