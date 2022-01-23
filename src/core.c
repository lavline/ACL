#include"core.h"

void insert(Cell* c_list, rule* r)
{
	rule* p = r;
	unsigned int c_id[LEVEL]; //index cell id
	data _d;
	memcpy(&_d, p, sizeof(data));
	_d.source_mask = (unsigned short)p->source_mask;
	_d.destination_mask = (unsigned short)p->destination_mask;

	unsigned int s_mask = (unsigned int)(p->source_mask >> 3);
	if ((unsigned int)p->protocol[0] == 0)c_id[0] = PROTO_END_CELL;
	else {
		switch ((unsigned int)p->protocol[1])
		{
		case TCP:
			c_id[0] = 0;
			break;
		case ICMP:
			c_id[0] = 1;
			break;
		case UDP:
			c_id[0] = 2;
			break;
		default:
			fprintf(stderr, "Rule %d Error - unknown message protocol %u !\n", p->PRI, p->protocol[1]);
			return;
		}
	}
	switch (s_mask)
	{
	case 0:
		c_id[IP_LAYER_1] = IP_EDN_CELL_1;
		c_id[IP_LAYER_2] = IP_EDN_CELL_2;
		c_id[IP_LAYER_3] = IP_EDN_CELL_3;
		break;
	case 1:
		c_id[IP_LAYER_1] = p->source_ip[3] >> IP_WIDTH_1;
		c_id[IP_LAYER_2] = IP_EDN_CELL_2;
		c_id[IP_LAYER_3] = IP_EDN_CELL_3;
		break;
	case 2:
		c_id[IP_LAYER_1] = p->source_ip[3] >> IP_WIDTH_1;
		c_id[IP_LAYER_2] = p->source_ip[2] >> IP_WIDTH_2;
		c_id[IP_LAYER_3] = IP_EDN_CELL_3
		break;
	default:
		c_id[IP_LAYER_1] = p->source_ip[3] >> IP_WIDTH_1;
		c_id[IP_LAYER_2] = p->source_ip[2] >> IP_WIDTH_2;
		c_id[IP_LAYER_3] = p->source_ip[1] >> IP_WIDTH_3;
		break;
	}
	if (p->destination_port[0] == p->destination_port[1])c_id[PORT_LAYER] = p->destination_port[0] >> PORT_WIDTH;
	else if(p->destination_port[0] >> PORT_WIDTH == p->destination_port[1] >> PORT_WIDTH)c_id[PORT_LAYER] = p->destination_port[0] >> PORT_WIDTH;
	else c_id[PORT_LAYER] = PORT_END_CELL;

	int id = (((c_id[0] * IP_SIZE_1 + c_id[IP_LAYER_1]) * IP_SIZE_2 + c_id[IP_LAYER_2]) * IP_SIZE_3 + c_id[IP_LAYER_3]) * PORT_SIZE + c_id[PORT_LAYER];
	add_data(c_list + id, &_d);
}


int match(Cell* c_list, message* m)
{
	Cell* _c = c_list;
	message* p = m;
	unsigned int e_protocol, es_ip, ed_ip;
	unsigned short es_port, ed_port;
	e_protocol = p->protocol;
	memcpy(&es_ip, p->source_ip, 4);
	memcpy(&ed_ip, p->destination_ip, 4);
	es_port = p->source_port;
	ed_port = p->destination_port;

	unsigned int c_id[LEVEL][2];
	switch ((unsigned int)p->protocol)
	{
	case TCP:
		c_id[0][0] = 0;
		break;
	case ICMP:
		c_id[0][0] = 1;
		break;
	case UDP:
		c_id[0][0] = 2;
		break;
	default:
		//fprintf(stderr, "Message Error - unknown message protocol %u!\n", e_protocol);
		c_id[0][0] = PROTO_END_CELL;
		break;
	}
	c_id[0][1] = PROTO_END_CELL;
	c_id[IP_LAYER_1][0] = p->source_ip[3] >> IP_WIDTH_1;
	c_id[IP_LAYER_1][1] = IP_EDN_CELL_1;
	c_id[IP_LAYER_2][0] = p->source_ip[2] >> IP_WIDTH_2;
	c_id[IP_LAYER_2][1] = IP_EDN_CELL_2;
	c_id[IP_LAYER_3][0] = p->source_ip[1] >> IP_WIDTH_3;
	c_id[IP_LAYER_3][1] = IP_EDN_CELL_3;
	c_id[PORT_LAYER][0] = p->destination_port >> PORT_WIDTH;
	c_id[PORT_LAYER][1] = PORT_END_CELL;

	int res = 0x7FFFFFFF;
	for (int i = 0; i < 2; i++) {
		int id_1 = c_id[0][i] * IP_SIZE_1; // next layer start id
		for (int j = 0; j < 2; j++) {
			int id_2 = (id_1 + c_id[IP_LAYER_1][j]) * IP_SIZE_2;
			for (int k = 0; k < 2; k++) {
				int id_3 = (id_2 + c_id[IP_LAYER_2][k]) * IP_SIZE_3;
				for (int v = 0; v < 2; v++) {
					int id_4 = (id_3 + c_id[IP_LAYER_3][v]) * PORT_SIZE;
					for (int w = 0; w < 2; w++) {
						int tar_id = id_4 + c_id[PORT_LAYER][w]; // the target cell id
						int _size = _c[tar_id].size;
						if (_size == 0)continue;
						data* _list = _c[tar_id].list;
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
							if (es_port < _d->source_port[0] || _d->source_port[1] < es_port)continue;  //if source port not match, check next
							if (ed_port < _d->destination_port[0] || _d->destination_port[1] < ed_port)continue;  //if destination port not match, check next
							res = _d->PRI;
							break;
						}
					}
				}
			}
		}
	}

	if (res == 0x7FFFFFFF)res = -1;
	return res;
}

int match_with_log(Cell* c_list, message* m, int *_cycle)
{
	uint64_t time_1, time_2;

	time_1 = GetCPUCycle();

	Cell* _c = c_list;
	message* p = m;
	unsigned int e_protocol, es_ip, ed_ip;
	unsigned short es_port, ed_port;
	e_protocol = p->protocol;
	memcpy(&es_ip, p->source_ip, 4);
	memcpy(&ed_ip, p->destination_ip, 4);
	es_port = p->source_port;
	ed_port = p->destination_port;

	unsigned int c_id[LEVEL][2];
	switch ((unsigned int)p->protocol)
	{
	case TCP:
		c_id[0][0] = 0;
		break;
	case ICMP:
		c_id[0][0] = 1;
		break;
	case UDP:
		c_id[0][0] = 2;
		break;
	default:
		//fprintf(stderr, "Message Error - unknown message protocol %u!\n", e_protocol);
		c_id[0][0] = PROTO_END_CELL;
		break;
	}
	c_id[0][1] = PROTO_END_CELL;
	c_id[IP_LAYER_1][0] = p->source_ip[3] >> IP_WIDTH_1;
	c_id[IP_LAYER_1][1] = IP_EDN_CELL_1;
	c_id[IP_LAYER_2][0] = p->source_ip[2] >> IP_WIDTH_2;
	c_id[IP_LAYER_2][1] = IP_EDN_CELL_2;
	c_id[IP_LAYER_3][0] = p->source_ip[1] >> IP_WIDTH_3;
	c_id[IP_LAYER_3][1] = IP_EDN_CELL_3;
	c_id[PORT_LAYER][0] = p->destination_port >> PORT_WIDTH;
	c_id[PORT_LAYER][1] = PORT_END_CELL;

	int res = 0x7FFFFFFF;
	for (int i = 0; i < 2; i++) {
		int id_1 = c_id[0][i] * IP_SIZE_1; // next layer start id
		for (int j = 0; j < 2; j++) {
			int id_2 = (id_1 + c_id[IP_LAYER_1][j]) * IP_SIZE_2;
			for (int k = 0; k < 2; k++) {
				int id_3 = (id_2 + c_id[IP_LAYER_2][k]) * IP_SIZE_3;
				for (int v = 0; v < 2; v++) {
					int id_4 = (id_3 + c_id[IP_LAYER_3][v]) * PORT_SIZE;
					for (int w = 0; w < 2; w++) {
						int tar_id = id_4 + c_id[PORT_LAYER][w]; // the target cell id
						int _size = _c[tar_id].size;
						if (_size == 0)continue;
						data* _list = _c[tar_id].list;
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
							if (es_port < _d->source_port[0] || _d->source_port[1] < es_port)continue;  //if source port not match, check next
							if (ed_port < _d->destination_port[0] || _d->destination_port[1] < ed_port)continue;  //if destination port not match, check next
							res = _d->PRI;
							break;
						}
					}
				}
			}
		}
	}

	time_2 = GetCPUCycle();

	*_cycle = time_2 - time_1;
	//printf("matching instruction cycle : %d\n", instruction_cycle);

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
	int _log[LEVEL][IP_SIZE_2] = { 0 };

	for (int i = 0; i < data->size; i++) {
		rule* p = data->list + i;
		unsigned int c_id[LEVEL]; //index cell id

		unsigned int s_mask = (unsigned int)(p->source_mask >> 3);
		if ((unsigned int)p->protocol[0] == 0)c_id[0] = PROTO_END_CELL;
		else {
			switch ((unsigned int)p->protocol[1])
			{
			case TCP:
				c_id[0] = 0;
				break;
			case ICMP:
				c_id[0] = 1;
				break;
			case UDP:
				c_id[0] = 2;
				break;
			default:
				fprintf(stderr, "Rule %d Error - unknown message protocol %u !\n", p->PRI, p->protocol[1]);
				return;
			}
		}
		switch (s_mask)
		{
		case 0:
			c_id[IP_LAYER_1] = IP_EDN_CELL_1;
			c_id[IP_LAYER_2] = IP_EDN_CELL_2;
			c_id[IP_LAYER_3] = IP_EDN_CELL_3;
			break;
		case 1:
			c_id[IP_LAYER_1] = p->source_ip[3] >> IP_WIDTH_1;
			c_id[IP_LAYER_2] = IP_EDN_CELL_2;
			c_id[IP_LAYER_3] = IP_EDN_CELL_3;
			break;
		case 2:
			c_id[IP_LAYER_1] = p->source_ip[3] >> IP_WIDTH_1;
			c_id[IP_LAYER_2] = p->source_ip[2] >> IP_WIDTH_2;
			c_id[IP_LAYER_3] = IP_EDN_CELL_3
				break;
		default:
			c_id[IP_LAYER_1] = p->source_ip[3] >> IP_WIDTH_1;
			c_id[IP_LAYER_2] = p->source_ip[2] >> IP_WIDTH_2;
			c_id[IP_LAYER_3] = p->source_ip[1] >> IP_WIDTH_3;
			break;
		}
		if (p->destination_port[0] == p->destination_port[1])c_id[PORT_LAYER] = p->destination_port[0] >> PORT_WIDTH;
		else if (p->destination_port[0] >> PORT_WIDTH == p->destination_port[1] >> PORT_WIDTH)c_id[PORT_LAYER] = p->destination_port[0] >> PORT_WIDTH;
		else c_id[PORT_LAYER] = PORT_END_CELL;

		for (int j = 0; j < LEVEL; j++) {
			_log[j][c_id[j]]++;
		}
	}

	FILE* fp = NULL;
	fp = fopen("analyse_data.txt", "w");
	for (int i = 0; i < LEVEL; i++) {
		fprintf(fp, "%d ", i);
		for (int j = 0; j < IP_SIZE_2; j++)
			fprintf(fp, "%d ", _log[i][j]);
		fprintf(fp, "\n");
	}
	fclose(fp);
}

double get_memory(Cell* c_list)
{
	size_t mem = CELL_SIZE * sizeof(Cell);
	for (int i = 0; i < CELL_SIZE; i++) {
		mem = mem + (c_list + i)->capacity * sizeof(data);
	}
	printf("%u B\n", mem);
	double res = (double)mem / 1024.0 / 1024.0;
	return res;
}
