#include"core.h"
#include"read.h"

int main() {
	ACL_rules datasets = { 0,0,0 };
	Cell* index;
	index = (Cell*)calloc(15001, sizeof(Cell));
	read_rules("acl1_256k.txt", &datasets);
	for (int i = 0; i < datasets.size; i++)
		insert(index, datasets.list + i);
	Cell* c_test = index + 2048;
	
	message m_test = { 6, 205, 234, 20, 189, 205, 165, 111, 96, 22, 5400 };
	for (int i = 0; i < 1000; i++) {
		int res = match(index, &m_test);
		printf("satisfied rule id: %d\n", res);
	}
	return 0;
}

