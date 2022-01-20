#include"core.h"

void insert(Cell* c_list, rule* r)
{
	rule* p = r;
	int c_id[6]; //index cell id
	data _d;
	memcpy(&_d, p, sizeof(data));
	_d.source_mask = (unsigned short)p->source_mask;
	_d.destination_mask = (unsigned short)p->destination_mask;
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
		c_id[1] = c_id[2] = 4;
		break;
	case 1:
		c_id[1] = (unsigned int)(p->source_ip[3] >> 6);
		c_id[2] = 4;
		break;
	default:
		c_id[1] = (unsigned int)(p->source_ip[3] >> 6);
		c_id[2] = (unsigned int)(p->source_ip[2] >> 6);
		break;
	}
	switch (d_mask)
	{
	case 0:
		c_id[3] = c_id[4] = 4;
		break;
	case 1:
		c_id[3] = (unsigned int)(p->destination_ip[3] >> 6);
		c_id[4] = 4;
		break;
	default:
		c_id[3] = (unsigned int)(p->destination_ip[3] >> 6);
		c_id[4] = (unsigned int)(p->destination_ip[2] >> 6);
		break;
	}
	if (p->destination_port[0] == p->destination_port[1])c_id[5] = (unsigned int)(p->destination_port[0] >> 13);
	else c_id[5] = 8;
	int id = ((((c_id[0] * 5 + c_id[1]) * 5 + c_id[2]) * 5 + c_id[3]) * 5 + c_id[4]) * 8 + c_id[5];
	add_data(c_list + id, &_d);
}

int match(Cell* c_list, message* m)
{
	uint64_t time_1, time_2;
	
	time_1 = GetCPUCycle();
	Cell* _c = c_list;
	message* p = m;
	int c_id[6][2];
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
		break;
	}
	c_id[1][0] = (unsigned int)(p->source_ip[3] >> 6);
	c_id[1][1] = 4;
	c_id[2][0] = (unsigned int)(p->source_ip[2] >> 6);
	c_id[2][1] = 4;
	c_id[3][0] = (unsigned int)(p->destination_ip[3] >> 6);
	c_id[3][1] = 4;
	c_id[4][0] = (unsigned int)(p->destination_ip[2] >> 6);
	c_id[4][1] = 4;
	c_id[5][0] = (unsigned int)(p->destination_port >> 13);
	c_id[5][1] = 8;

	int res = 0x7FFFFFFF;
	unsigned int es_ip, ed_ip;
	memcpy(&es_ip, p->source_ip, 4);
	memcpy(&ed_ip, p->destination_ip, 4);

	for (int i = 0; i < 2; i++) {
		int id_1 = c_id[0][i] * 5;
		for (int j = 0; j < 2; j++) {
			int id_2 = (id_1 + c_id[1][j]) * 5;
			for (int k = 0; k < 2; k++) {
				int id_3 = (id_2 + c_id[2][k]) * 5;
				for (int r = 0; r < 2; r++) {
					int id_4 = (id_3 + c_id[3][r]) * 5;
					for (int v = 0; v < 2; v++) {
						int id_5 = (id_4 + c_id[4][v]) * 8;
						for (int w = 0; w < 2; w++) {
							int id_6 = id_5 + c_id[5][w];
							int _size = _c[id_6].size;
							if (_size == 0)continue;
							data* _list = _c[id_6].list;
							unsigned int _ip;
							for (int u = 0; u < _size; u++) { //check in cell
								data* _d = _list + u;
								if (res < _d->PRI)break;
								unsigned int m_bit = 32 - (unsigned int)_d->source_mask;  //comput the bit number need to move
								memcpy(&_ip, _d->source_ip, 4);
								if (es_ip >> m_bit != _ip >> m_bit)continue;  //if source ip not match, check next
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
		}
	}
	if (res == 0x7FFFFFFF)res = -1;
	time_2 = GetCPUCycle();
	int instruction_cycle = time_2 - time_1;
	printf("matching instruction cycle: %d\n", instruction_cycle);
	return res;
}
