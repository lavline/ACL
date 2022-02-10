#include"core.h"
#include"read.h"

int main() {

#if PROTO
	printf("protocol %d ", PROTO_LAYER);
#endif
#if SIP_1
	printf("s_ip_1 %d ", SIP_1_LAYER);
#endif
#if SIP_2
	printf("s_ip_2 %d ", SIP_2_LAYER);
#endif
#if SIP_3
	printf("s_ip_3 %d ", SIP_3_LAYER);
#endif
#if SIP_4
	printf("s_ip_4 %d ", SIP_4_LAYER);
#endif
#if DIP_1
	printf("d_ip_1 %d ", DIP_1_LAYER);
#endif
#if DIP_2
	printf("d_ip_2 %d ", DIP_2_LAYER);
#endif
#if DIP_3
	printf("d_ip_3 %d ", DIP_3_LAYER);
#endif
#if DIP_4
	printf("d_ip_4 %d ", DIP_4_LAYER);
#endif
#if SPORT
	printf("s_port %d ", SPORT_LAYER);
#endif
#if DPORT
	printf("d_port %d ", DPORT_LAYER);
#endif
	printf("\n");

	ACL_rules datasets = { 0,0,0 };
	ACL_messages message_sets = { 0,0,0 };
	Cell* index;
	index = (Cell*)calloc(CELL_SIZE, sizeof(Cell));
	read_rules("/home/lzhy/ACL_dataset/fw1_256k.txt", &datasets);
	read_messages("/home/lzhy/ACL_dataset/fw1_256k_trace.txt", &message_sets);

	for (int i = 0; i < datasets.size; i++) {
		insert(index, datasets.list + i);
	}

	//analyse_log(&datasets);
	//get_cell_size(index);
	//printf("%f MB\n", get_memory(index));
	
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

