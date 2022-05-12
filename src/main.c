#include <stdlib.h>
#include"core.h"
#include"read.h"

int main() {
	for (int i = 0; i < 4; i++)max_pri[i] = 0x7FFFFFFF;
	cell_size[0] = CELL_SIZE;
	cell_size[1] = 16974593;
	cell_size[2] = 17007489;
	cell_size[3] = 2171136;

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
	struct timespec it1, it2;
	clock_gettime(CLOCK_REALTIME, &it1);
	int tree_number = 4;
	CellList index[4] = {0};
	uint16_t** index_hash;
	Cell** index_temp;
	index_temp = (Cell**)calloc(tree_number, sizeof(Cell*));
	index_hash = (uint16_t**)calloc(tree_number, sizeof(uint16_t*));
	for (int i = 0; i < tree_number; i++) {
		index_temp[i] = (Cell*)calloc(cell_size[i], sizeof(Cell));
		index_hash[i] = (uint16_t*)calloc(cell_size[i], sizeof(uint16_t));
	}
	uint64_t insert_cycle = GetCPUCycle();
	for (int i = 0; i < datasets.size; i++) {
		insert(index_temp, datasets.list + index_array[i]);
		//insert(index, datasets.list + i);
	}
	{
		{//处理特殊的cell
			int t_id = 2; int h_id = 17007488;
			data* _d = index_temp[t_id][h_id].list;
			max_pri[3] = _d->PRI;
			for (int i = 0; i < index_temp[t_id][h_id].size; i++) {
				int c_id[3];
				c_id[0] = _d->source_ip[3];
				if (_d->source_mask > 15)c_id[1] = _d->source_ip[2];
				else c_id[1] = 256;
				if (_d->source_mask > 20)c_id[2] = _d->source_ip[1] >> 3;
				else c_id[2] = 32;
				add_data(index_temp[3] + (((c_id[0] * 257) + c_id[1]) * 33 + c_id[2]), _d);
				++_d;
			}
			free(index_temp[t_id][h_id].list);
			index_temp[t_id][h_id].size = index_temp[t_id][h_id].capacity = 0;
		}
		
		for (int x = 0; x < 4; x++) {
			int j = 1;
			for (int i = 0; i < cell_size[x]; i++) {
				if (index_temp[x][i].size > 0) {
					add_cell(&index[x], index_temp[x] + i);
					index_hash[x][i] = j++;
				}
			}
		}
	}
	clock_gettime(CLOCK_REALTIME, &it2);
	insert_cycle = GetCPUCycle() - insert_cycle;
	printf("avg insert cycle: %f\n", (double)insert_cycle / datasets.size);
	printf("insert time: %f\n", (double)(it2.tv_sec - it1.tv_sec) + (it2.tv_nsec - it1.tv_nsec) / 1000000000.0);
	for (int i = 0; i < tree_number; i++)free(index_temp[i]);
	free(index_temp);
	free(index_array);

	/*{
		FILE* cell_fp = NULL;
		cell_fp = fopen("index.txt", "w");
		for (int k = 0; k < tree_number; k++) {
			for (int i = 0; i < index[k].size; i++) {
				if (index[k].list[i].size > 100) {
					fprintf(cell_fp, "tree_id=%d, cell_id=%d, cell_size=%d\n", k, i, index[k].list[i].size);
					data* _d = index[k].list[i].list;
					for (int j = 0; j < index[k].list[i].size; j++)fprintf(cell_fp, "\tsip=%u.%u.%u.%u/%u,dip=%u.%u.%u.%u/%u,sport=%u:%u,dport=%u:%u,proto=%u,index=%u\n",
						_d[j].source_ip[3], _d[j].source_ip[2], _d[j].source_ip[1], _d[j].source_ip[0], _d[j].source_mask,
						_d[j].destination_ip[3], _d[j].destination_ip[2], _d[j].destination_ip[1], _d[j].destination_ip[0], _d[j].destination_mask,
						_d[j].source_port[0], _d[j].source_port[1], _d[j].destination_port[0], _d[j].destination_port[1], (unsigned int)(_d[j].protocol[1]), _d[j].PRI);
				}
			}
		}
		fclose(cell_fp);
	}*/

	//check_indexCell(index + 4934205);
	for (int r_num = 0; r_num < 6; r_num++) {
#if ENABLE_ANALYSE
		analyse_log(&datasets);
		get_cell_size(index);
		printf("%f MB\n", get_memory(index));
#endif
		int res = 0;
		int cycle = 0;
		double total_cycle = 0;
		MatchLog match_log = { 0 };

		printf("match start...\n");
#if ENABLE_LOG
		match_log.list = (LogInCell*)malloc(30 * sizeof(LogInCell));
#endif
		FILE* res_fp = NULL;
		res_fp = fopen("match_cycle.txt", "w");

		// match
		struct timespec t1, t2;
		double total_time = 0;
		for (int i = 0; i < message_sets.size; i++) {
			clock_gettime(CLOCK_REALTIME, &t1);
			res = match_with_log(index, message_sets.list + i, &cycle, &match_log, index_hash);
			clock_gettime(CLOCK_REALTIME, &t2);
			total_time += get_nano_time(&t1, &t2);
			total_cycle += cycle;
#if ENABLE_LOG
			fprintf(res_fp, "message %d match_rule %d cycle %d check_cells %d check_rules %d\n", i, res, cycle, match_log.rules, match_log.ele);
#if LOG_LEVEL == 2
			for (int j = 0; j < match_log.rules; j++) {
				fprintf(res_fp, "\ttree_id=%d id=%d ", match_log.list[j].tree_id, match_log.list[j].id);
				//for (int k = 0; k < LEVEL; k++) fprintf(res_fp, "%d ", match_log.list[j].layer[k]);
				fprintf(res_fp, "size %d CRul %d HPRI %d match %d\n",
					match_log.list[j].size, match_log.list[j].rules, match_log.list[j].HPRI, match_log.list[j].match);
			}
#endif
#else
			fprintf(res_fp, "message %d match_rule %d cycle %d\n", i, res, cycle);
#endif
		}

		fclose(res_fp);
		printf("average_match_cycle %f\n", total_cycle / (double)message_sets.size);
		printf("average_match_time %f\n\n", total_time / (double)message_sets.size / 1000.0);
	}

	for (int j = 0; j < 4; j++) {
		for (int i = 0; i < index[j].size; i++) {
			/*if (index->list[i].enable_subcell) {
				for (int j = 0; j < index->list[i].subCell->size; j++)free(index->list[i].subCell->list);
				free(index->list[i].subCell);
			}else*/
			free(index[j].list[i].list);  // free cell list
		}
		free(index[j].list);
	}
	for (int i = 0; i < 4; i++)free(index_hash[i]);
	//free(index);  // free cell
	free(message_sets.list); // free message list
	free(datasets.list);  // free dataset list
#if ENABLE_LOG
	free(match_log.list);  // free log list
#endif
	printf("program complete\n");
	return 0;
}

