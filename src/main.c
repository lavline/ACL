#include"core.h"
#include"read.h"

int main() {
	ACL_rules datasets = { 0,0,0 };
	ACL_messages message_sets = { 0,0,0 };
	Cell* index;
	index = (Cell*)calloc(CELL_SIZE, sizeof(Cell));
	read_rules("acl1_256k.txt", &datasets);
	read_messages("acl1_256k_trace.txt", &message_sets);

	//rule* r_check = datasets.list + 65885;
	//message* m_check = message_sets.list + message_sets.size - 1;
	//insert(index, datasets.list + 65885);

	for (int i = 0; i < datasets.size; i++)
		insert(index, datasets.list + i);
	
	//Cell* c_test = index + 121275;
	//get_cell_size(index);
	//analyse_log(&datasets);
	
	int res = 0;
	int cycle = 0;
	FILE* res_fp = NULL;
	res_fp = fopen("match_cycle.txt", "w");

	for (int i = 0; i < message_sets.size; i++) {
		res = match_with_log(index, message_sets.list + i, &cycle);
		fprintf(res_fp, "message %d match_rule %d cycle %d\n", i, res, cycle);
	}

	fclose(res_fp);
	/*
	message m_test_1 = { 6, 205, 234, 20, 189, 205, 165, 111, 96, 22, 1490 };
	message m_test_2 = { 6, 0, 0, 0, 127, 0, 0, 0, 0, 22, 5400 };
	message m_test_3 = { 1, 0, 0, 64, 60, 0, 0, 0, 0, 22, 5400 };
	int res = 0;
	for (int i = 0; i < 10; i++) {
		res = match(index, &m_test_1);
		printf("satisfied rule id: %d\n", res);
	}
	res = match(index, &m_test_2);
	printf("satisfied rule id: %d\n", res);
	res = match(index, &m_test_3);
	printf("satisfied rule id: %d\n", res);
	res = match(index, &m_test_1);
	printf("satisfied rule id: %d\n", res);
	*/

	for (int i = 0; i < CELL_SIZE; i++)free(index[i].list);
	free(index);
	free(message_sets.list);
	free(datasets.list);
	return 0;
}

