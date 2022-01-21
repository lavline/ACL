#include"core.h"

void insert(Cell* c_list, rule* r)
{
	rule* p = r;
	int c_id[LEVEL]; //index cell id
	data _d;
	memcpy(&_d, p, sizeof(data));
	_d.source_mask = (unsigned short)p->source_mask;
	_d.destination_mask = (unsigned short)p->destination_mask;

	unsigned int s_mask = (unsigned int)(p->source_mask >> 3);
	switch (p->protocol)
	{
	case 0:
		c_id[0] = 2;
		break;
	case 1:
		c_id[0] = 1;
		break;
	case 6:
		c_id[0] = 0;
		break;
	default:
		break;
	}
	switch (s_mask)
	{
	case 0:
		c_id[1] = c_id[2] = IP_EDN_CELL;
		break;
	case 1:
		c_id[1] = (unsigned int)(p->source_ip[3] >> IP_WIDTH);
		c_id[2] = IP_EDN_CELL;
		break;
	default:
		c_id[1] = (unsigned int)(p->source_ip[3] >> IP_WIDTH);
		c_id[2] = (unsigned int)(p->source_ip[2] >> IP_WIDTH);
		break;
	}
	if (p->destination_port[0] == p->destination_port[1])c_id[3] = (unsigned int)(p->destination_port[0] >> PORT_WIDTH);
	else if((unsigned int)(p->destination_port[0] >> PORT_WIDTH) == (unsigned int)(p->destination_port[1] >> PORT_WIDTH))c_id[3] = (unsigned int)(p->destination_port[0] >> PORT_WIDTH);
	else c_id[3] = PORT_END_CELL;

	int id = ((c_id[0] * IP_SIZE + c_id[1]) * IP_SIZE + c_id[2]) * PORT_SIZE + c_id[3];
	add_data(c_list + id, &_d);
}

int match(Cell* c_list, message* m)
{
	uint64_t time_1, time_2;
	
	time_1 = GetCPUCycle();

	Cell* _c = c_list;
	message* p = m;
	int c_id[LEVEL][2];
	switch (p->protocol)
	{
	case 1:
		c_id[0][0] = 1;
		c_id[0][1] = 2;
		break;
	case 6:
		c_id[0][0] = 0;
		c_id[0][1] = 2;
		break;
	default:
		fprintf(stderr, "Error - unknown message protocol!\n");
		break;
	}
	c_id[1][0] = (unsigned int)(p->source_ip[3] >> IP_WIDTH);
	c_id[1][1] = IP_EDN_CELL;
	c_id[2][0] = (unsigned int)(p->source_ip[2] >> IP_WIDTH);
	c_id[2][1] = IP_EDN_CELL;
	c_id[3][0] = (unsigned int)(p->destination_port >> PORT_WIDTH);
	c_id[3][1] = PORT_END_CELL;

	int res = 0x7FFFFFFF;
	unsigned int es_ip, ed_ip;
	memcpy(&es_ip, p->source_ip, 4);
	memcpy(&ed_ip, p->destination_ip, 4);

	for (int i = 0; i < 2; i++) {
		int id_1 = c_id[0][i] * IP_SIZE;
		for (int j = 0; j < 2; j++) {
			int id_2 = (id_1 + c_id[1][j]) * IP_SIZE;
			for (int v = 0; v < 2; v++) {
				int id_3 = (id_2 + c_id[2][v]) * PORT_SIZE;
				for (int w = 0; w < 2; w++) {
					int id_4 = id_3 + c_id[3][w];
					int _size = _c[id_4].size;
					if (_size == 0)continue;
					data* _list = _c[id_4].list;
					unsigned int _ip;
					for (int u = 0; u < _size; u++) { //check in cell
						data* _d = _list + u;
						if (res < _d->PRI)break;
						unsigned int m_bit = 32 - (unsigned int)_d->source_mask;  //comput the bit number need to move
						memcpy(&_ip, _d->source_ip, 4);
						if (es_ip >> m_bit != _ip >> m_bit)continue;  //if source ip not match, check next
						m_bit = 32 - (unsigned int)_d->destination_mask;  //comput the bit number need to move
						memcpy(&_ip, _d->destination_ip, 4);
						if (ed_ip >> m_bit != _ip >> m_bit)continue;  //if destination ip not match, check next
						if (p->source_port < _d->source_port[0] || _d->source_port[1] < p->source_port)continue;  //if source port not match, check next
						if (p->destination_port < _d->destination_port[0] || _d->destination_port[1] < p->destination_port)continue;  //if destination port not match, check next
						res = _d->PRI;
						break;
					}
				}
			}
		}
	}

	if (res == 0x7FFFFFFF)res = -1;

	time_2 = GetCPUCycle();

	int instruction_cycle = time_2 - time_1;
	printf("matching instruction cycle : %d\n", instruction_cycle);

	return res;
}

void get_cell_size(Cell* c)
{
	FILE* fp = NULL;
	fp = fopen("cell_size.txt", "w");
	for (int i = 0; i < CELL_SIZE; i++) {
		fprintf(fp, "ID: %d size: %d\n", i, (c + i)->size);
	}
	fclose(fp);
}

void analyse_log(ACL_rules* data)
{
	int _log[LEVEL][PORT_SIZE] = { 0 };

	for (int i = 0; i < data->size; i++) {
		rule* p = data->list + i;
		int c_id[LEVEL]; //index cell id
		unsigned int s_mask = (unsigned int)(p->source_mask >> 3);
		unsigned int d_mask = (unsigned int)(p->destination_mask >> 3);
		switch (p->protocol)
		{
		case 0:
			c_id[0] = 2;
			break;
		case 1:
			c_id[0] = 1;
			break;
		case 6:
			c_id[0] = 0;
			break;
		default:
			break;
		}
		switch (s_mask)
		{
		case 0:
			c_id[1] = c_id[2] = IP_EDN_CELL;
			break;
		case 1:
			c_id[1] = (unsigned int)(p->source_ip[3] >> IP_WIDTH);
			c_id[2] = IP_EDN_CELL;
			break;
		default:
			c_id[1] = (unsigned int)(p->source_ip[3] >> IP_WIDTH);
			c_id[2] = (unsigned int)(p->source_ip[2] >> IP_WIDTH);
			break;
		}
		if (p->destination_port[0] == p->destination_port[1])c_id[3] = (unsigned int)(p->destination_port[0] >> PORT_WIDTH);
		else if ((unsigned int)(p->destination_port[0] >> PORT_WIDTH) == (unsigned int)(p->destination_port[1] >> PORT_WIDTH))c_id[3] = (unsigned int)(p->destination_port[0] >> PORT_WIDTH);
		else c_id[3] = PORT_END_CELL;
		int id = ((c_id[0] * IP_SIZE + c_id[1]) * IP_SIZE + c_id[2]) * PORT_SIZE + c_id[3];

		for (int j = 0; j < LEVEL; j++) {
			_log[j][c_id[j]]++;
		}
	}

	FILE* fp = NULL;
	fp = fopen("analyse_data.txt", "w");
	for (int i = 0; i < LEVEL; i++) {
		fprintf(fp, "%d ", i);
		for (int j = 0; j < PORT_SIZE; j++)
			fprintf(fp, "%d ", _log[i][j]);
		fprintf(fp, "\n");
	}
	fclose(fp);
}
