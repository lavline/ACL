#include <stdlib.h>
#include <string.h>
#include"core.h"
#include"read.h"

int main() {
	if (ENABLE_ANALYSE)printf("Enable Analyse\n");
	if (ENABLE_LOG)printf("Enable Log\n");
	if (ENABLE_ANALYSE || ENABLE_LOG)printf("\n");
	if (!check_configure())return -1;
	//printf("%ld\n", sizeof(int*));

	char* dir = "/root/ACL_dataset/";
	char* files[] = { "acl1_256k", "acl2_256k", "acl3_256k" , "acl4_256k" , "acl5_256k",
					  "fw1_256k", "fw2_256k" ,"fw3_256k" ,"fw4_256k" ,"fw5_256k" , "ipc1_256k", "ipc2_256k" };

	double total_avg_cycle = 0;
	for (int i = 0; i < 12; i++) {
		ACL_rules datasets = { 0,0,0 };
		ACL_messages message_sets = { 0,0,0 };
		Cell* index;
		index = (Cell*)calloc(CELL_SIZE, sizeof(Cell));

		char rule_file[50] = "";
		char trace_file[50] = "";
		char result_file[50] = "match_cycle_";
		strcat(rule_file, dir);
		strcat(rule_file, files[i]);
		strcat(rule_file, ".txt");
		strcat(trace_file, dir);
		strcat(trace_file, files[i]);
		strcat(trace_file, "_trace-1.txt");
		strcat(result_file, files[i]);
		strcat(result_file, ".txt");

		//printf("%s\n", rule_file);
		//printf("%s\n", trace_file);
		//printf("%s\n", result_file);

		read_rules(rule_file, &datasets);
		read_messages(trace_file, &message_sets);

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
		//get_cell_size(index);
		printf("%f MB\n", get_memory(index));
#endif
		int res = 0;
		int cycle = 0;
		MatchLog match_log;
		match_log.list = (LogInCell*)malloc((1 << LEVEL) * sizeof(LogInCell));
		FILE* res_fp = NULL;
		res_fp = fopen(result_file, "w");

		// match
		double avg_cycle = 0;
		for (int i = 0; i < message_sets.size; i += RECORD_STEP) {
			res = match_with_log(index, message_sets.list + i, &cycle, &match_log);
#if ENABLE_LOG
			fprintf(res_fp, "message %d match_rule %d cycle %f check_rules %d check_element %d\n", i + RECORD_STEP, res, (double)cycle / RECORD_STEP, match_log.rules, match_log.ele);
			for (int j = 0; j < (1 << LEVEL); j++) {
				fprintf(res_fp, "\tid %d ", match_log.list[j].id);
				for (int k = 0; k < LEVEL; k++) fprintf(res_fp, "%d ", match_log.list[j].layer[k]);
				fprintf(res_fp, "size %d CRul %d CEle %d HPRI %d match %d\n",
					match_log.list[j].size, match_log.list[j].rules, match_log.list[j].ele, match_log.list[j].HPRI, match_log.list[j].match);
			}
#else
			fprintf(res_fp, "message %d match_rule %d cycle %f\n", i + RECORD_STEP, res, (double)cycle / RECORD_STEP);
			avg_cycle += cycle;
#endif
		}
		fclose(res_fp);
		printf("%s average_match_cycle %f\n\n", files[i], avg_cycle / message_sets.size);
		total_avg_cycle += avg_cycle / message_sets.size;

		for (int i = 0; i < CELL_SIZE; i++)free(index[i].list);  // free cell list
		free(index);  // free cell
		free(message_sets.list); // free message list
		free(datasets.list);  // free dataset list
		free(match_log.list);  // free log list
	}
	printf("total average cycle: %f\n", total_avg_cycle / 12.0);
	printf("program complete\n");
	return 0;
}

