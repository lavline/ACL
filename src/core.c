#include"core.h"

void insert(Cell* c_list, rule* r)
{
	rule* p = r;
	unsigned int c_id[LEVEL]; //index cell id
	data _d;
	memcpy(&_d, p, sizeof(data));

#if SIP_1 || SIP_2 || SIP_3 || SIP_4
	unsigned int s_mask = (unsigned int)(p->source_mask >> 3);
#endif
#if DIP_1 || DIP_2 || DIP_3 || DIP_4
	unsigned int d_mask = (unsigned int)(p->destination_mask >> 3);
#endif // DIP_1 || DIP_2 || DIP_3 || DIP_4

#if PROTO
	if ((unsigned int)p->protocol[0] == 0)c_id[PROTO_LAYER] = PROTO_END_CELL;
	else {
		switch ((unsigned int)p->protocol[1])
		{
		case TCP:
			c_id[PROTO_LAYER] = 0;
			break;
		case ICMP:
			c_id[PROTO_LAYER] = 1;
			break;
		case UDP:
			c_id[PROTO_LAYER] = 2;
			break;
		default:
			c_id[PROTO_LAYER] = PROTO_END_CELL;
			break;
		}
	}
#endif
#if SIP_1
	if (s_mask > 0)c_id[SIP_1_LAYER] = p->source_ip[3] >> SIP_WIDTH_1;
	else c_id[SIP_1_LAYER] = SIP_EDN_CELL_1;
#endif
#if SIP_2
	if (s_mask > 1)c_id[SIP_2_LAYER] = p->source_ip[2] >> SIP_WIDTH_2;
	else c_id[SIP_2_LAYER] = SIP_EDN_CELL_2;
#endif
#if SIP_3
	if (s_mask > 2)c_id[SIP_3_LAYER] = p->source_ip[1] >> SIP_WIDTH_3;
	else c_id[SIP_3_LAYER] = SIP_EDN_CELL_3;
#endif
#if SIP_4
	if (s_mask > 3)c_id[SIP_4_LAYER] = p->source_ip[0] >> SIP_WIDTH_4;
	else c_id[SIP_4_LAYER] = SIP_EDN_CELL_4;
#endif
#if DIP_1
	if (d_mask > 0)c_id[DIP_1_LAYER] = p->destination_ip[3] >> DIP_WIDTH_1;
	else c_id[DIP_1_LAYER] = DIP_EDN_CELL_1;
#endif
#if DIP_2
	if (d_mask > 1)c_id[DIP_2_LAYER] = p->destination_ip[2] >> DIP_WIDTH_2;
	else c_id[DIP_2_LAYER] = DIP_EDN_CELL_2;
#endif
#if DIP_3
	if (d_mask > 2)c_id[DIP_3_LAYER] = p->destination_ip[1] >> DIP_WIDTH_3;
	else c_id[DIP_3_LAYER] = DIP_EDN_CELL_3;
#endif
#if DIP_4
	if (d_mask > 3)c_id[DIP_4_LAYER] = p->destination_ip[0] >> DIP_WIDTH_4;
	else c_id[DIP_4_LAYER] = DIP_EDN_CELL_4;
#endif
#if SPORT
	if (p->source_port[0] >> SPORT_WIDTH == p->source_port[1] >> SPORT_WIDTH)c_id[SPORT_LAYER] = p->source_port[0] >> SPORT_WIDTH;
	else c_id[SPORT_LAYER] = SPORT_END_CELL;
#endif
#if DPORT
	if (p->destination_port[0] >> DPORT_WIDTH == p->destination_port[1] >> DPORT_WIDTH)c_id[DPORT_LAYER] = p->destination_port[0] >> DPORT_WIDTH;
	else c_id[DPORT_LAYER] = DPORT_END_CELL;
#endif

	int id = ((c_id[0] * LAYER_1 + c_id[1]) * LAYER_2 + c_id[2]) * LAYER_3 + c_id[3];
	//printf("%d %d\n", p->PRI, id);
	//for(int i=0;i<LEVEL;i++)printf("%d ", c_id[i]);
	//printf("\n");

	add_data(c_list + (((c_id[0] * LAYER_1 + c_id[1]) * LAYER_2 + c_id[2]) * LAYER_3 + c_id[3]), &_d);
}


int match(Cell* c_list, message* m)
{
	return -1;
}

int match_with_log(Cell* c_list, message* m, int *_cycle, MatchLog *log)
{
	uint64_t time_1, time_2;

	time_1 = GetCPUCycle();
	Cell* _c = c_list;
	message* p = m;
	unsigned int es_ip, ed_ip;
	unsigned char e_protocol;
	unsigned short es_port, ed_port;
	int res;

	for (int num = 0; num < 100; num++) {
#if ENABLE_LOG
		log->rules = log->ele = 0;
		memset(log->list, 0, 16 * sizeof(LogInCell));
#endif
		e_protocol = p->protocol;
		memcpy(&es_ip, p->source_ip, 4);
		memcpy(&ed_ip, p->destination_ip, 4);
		es_port = p->source_port;
		ed_port = p->destination_port;

		unsigned int c_id[LEVEL][2];

#if PROTO
		switch ((unsigned int)p->protocol)
		{
		case TCP:
			c_id[PROTO_LAYER][0] = 0;
			break;
		case ICMP:
			c_id[PROTO_LAYER][0] = 1;
			break;
		case UDP:
			c_id[PROTO_LAYER][0] = 2;
			break;
		default:
			c_id[PROTO_LAYER][0] = PROTO_END_CELL;
			break;
		}
		c_id[PROTO_LAYER][1] = PROTO_END_CELL;
#endif
#if SIP_1
		c_id[SIP_1_LAYER][0] = p->source_ip[3] >> SIP_WIDTH_1;
		c_id[SIP_1_LAYER][1] = SIP_EDN_CELL_1;
#endif
#if SIP_2
		c_id[SIP_2_LAYER][0] = p->source_ip[2] >> SIP_WIDTH_2;
		c_id[SIP_2_LAYER][1] = SIP_EDN_CELL_2;
#endif
#if SIP_3
		c_id[SIP_3_LAYER][0] = p->source_ip[1] >> SIP_WIDTH_3;
		c_id[SIP_3_LAYER][1] = SIP_EDN_CELL_3;
#endif
#if SIP_4
		c_id[SIP_4_LAYER][0] = p->source_ip[0] >> SIP_WIDTH_4;
		c_id[SIP_4_LAYER][1] = SIP_EDN_CELL_4;
#endif
#if DIP_1
		c_id[DIP_1_LAYER][0] = p->destination_ip[3] >> DIP_WIDTH_1;
		c_id[DIP_1_LAYER][1] = DIP_EDN_CELL_1;
#endif
#if DIP_2
		c_id[DIP_2_LAYER][0] = p->destination_ip[2] >> DIP_WIDTH_2;
		c_id[DIP_2_LAYER][1] = DIP_EDN_CELL_2;
#endif
#if DIP_3
		c_id[DIP_3_LAYER][0] = p->destination_ip[1] >> DIP_WIDTH_3;
		c_id[DIP_3_LAYER][1] = DIP_EDN_CELL_3;
#endif
#if DIP_4
		c_id[DIP_4_LAYER][0] = p->destination_ip[0] >> DIP_WIDTH_4;
		c_id[DIP_4_LAYER][1] = DIP_EDN_CELL_4;
#endif
#if SPORT
		c_id[SPORT_LAYER][0] = p->source_port >> SPORT_WIDTH;
		c_id[SPORT_LAYER][1] = SPORT_END_CELL;
#endif
#if DPORT
		c_id[DPORT_LAYER][0] = p->destination_port >> DPORT_WIDTH;
		c_id[DPORT_LAYER][1] = DPORT_END_CELL;
#endif	
		
		res = 0x7FFFFFFF;

#if ENABLE_LOG
		int cell_num = -1;
#endif

		for (int i = 0; i < 2; i++) {
			int id_1 = c_id[0][i] * LAYER_1;
			for (int j = 0; j < 2; j++) {
				int id_2 = (id_1 + c_id[1][j]) * LAYER_2;
				for (int v = 0; v < 2; v++) {
					int id_3 = (id_2 + c_id[2][v]) * LAYER_3;
					for (int w = 0; w < 2; w++) {
						Cell* q = _c + id_3 + c_id[3][w];
						int _size = q->size;

#if ENABLE_LOG
						cell_num++;
						log->list[cell_num].id = id_3 + c_id[3][w];
						log->list[cell_num].size = _size;
						log->list[cell_num].layer[0] = c_id[0][i];
						log->list[cell_num].layer[1] = c_id[1][j];
						log->list[cell_num].layer[2] = c_id[2][v];
						log->list[cell_num].layer[3] = c_id[3][w];
#endif

						if (_size == 0)continue;
						data* _d = q->list - 1;
						unsigned int _ip;
						for (int u = 0; u < _size; u++) { //check in cell
							++_d;

#if ENABLE_LOG
							log->rules++;
							log->list[cell_num].rules++;
							//__builtin_prefetch(_d + 4, 0);
							log->ele++;
							log->list[cell_num].ele++;
#endif

							if (res < _d->PRI)break; // check priority

#if ENABLE_LOG
							log->ele++;
							log->list[cell_num].ele++;
#endif

							if (e_protocol != _d->protocol[1] && _d->protocol[0] != 0)continue; // check protocol

#if ENABLE_LOG
							log->ele++;
							log->list[cell_num].ele++;
#endif

							unsigned int m_bit = 32 - (unsigned int)_d->destination_mask;  // comput the bit number need to move
							memcpy(&_ip, _d->destination_ip, 4);
							if (m_bit != 32 && ed_ip >> m_bit != _ip >> m_bit)continue;  // if destination ip not match, check next

#if ENABLE_LOG
							log->ele++;
							log->list[cell_num].ele++;
#endif

							m_bit = 32 - (unsigned int)_d->source_mask;  // comput the bit number need to move
							memcpy(&_ip, _d->source_ip, 4);
							if (m_bit != 32 && es_ip >> m_bit != _ip >> m_bit)continue;  // if source ip not match, check next

#if ENABLE_LOG
							log->ele++;
							log->list[cell_num].ele++;
#endif

							if (ed_port < _d->destination_port[0] || _d->destination_port[1] < ed_port)continue;  // if destination port not match, check next

#if ENABLE_LOG
							log->ele++;
							log->list[cell_num].ele++;
#endif

							if (es_port < _d->source_port[0] || _d->source_port[1] < es_port)continue;  // if source port not match, check next

							res = _d->PRI;
#if ENABLE_LOG
							log->list[cell_num].match = res;
#endif
							break;
						}
					}
				}
			}
		}

		if (res == 0x7FFFFFFF)res = -1;
		++p;
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

/***************************************************/
/*
*   analyse dateset:
*   对5元组进行分析，其中ip部分按照每个字节进行分析
*   协议层分为5个部分：TCP、ICMP、UDP、其他协议、通配符
*   IP层按字节进行分析，分为258个部分，其中0-255对应准确的ip，256对应范围ip，257对应通配ip即掩码为0
*   端口号分为258个部分，其中0-255对应被包含的端口区间，256对应无法包含的区间，257对应通配区间即[0-65535]
*/
/***************************************************/
void analyse_log(ACL_rules* data)
{
	int _log[11][258] = { 0 };

	for (int i = 0; i < data->size; i++) {
		rule* p = data->list + i;
		unsigned int c_id[11]; //index cell id
		unsigned int s_mask = (unsigned int)(p->source_mask >> 3);
		unsigned int d_mask = (unsigned int)(p->destination_mask >> 3);

		if ((unsigned int)p->protocol[0] == 0)c_id[0] = 4;
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
				c_id[0] = 3;
				break;
			}
		}
		if (p->source_mask == 0) {
			c_id[1] = 257;
			c_id[2] = 257;
			c_id[3] = 257;
			c_id[4] = 257;
		}
		else {
			switch (s_mask)
			{
			case 0:
				c_id[1] = 256;
				c_id[2] = 256;
				c_id[3] = 256;
				c_id[4] = 256;
				break;
			case 1:
				c_id[1] = p->source_ip[3];
				c_id[2] = 256;
				c_id[3] = 256;
				c_id[4] = 256;
				break;
			case 2:
				c_id[1] = p->source_ip[3];
				c_id[2] = p->source_ip[2];
				c_id[3] = 256;
				c_id[4] = 256;
				break;
			case 3:
				c_id[1] = p->source_ip[3];
				c_id[2] = p->source_ip[2];
				c_id[3] = p->source_ip[1];
				c_id[4] = 256;
				break;
			default:
				c_id[1] = p->source_ip[3];
				c_id[2] = p->source_ip[2];
				c_id[3] = p->source_ip[1];
				c_id[4] = p->source_ip[0];
				break;
			}
		}
		if (p->destination_mask == 0) {
			c_id[5] = 257;
			c_id[6] = 257;
			c_id[7] = 257;
			c_id[8] = 257;
		}
		else {
			switch (d_mask)
			{
			case 0:
				c_id[5] = 256;
				c_id[6] = 256;
				c_id[7] = 256;
				c_id[8] = 256;
				break;
			case 1:
				c_id[5] = p->destination_ip[3];
				c_id[6] = 256;
				c_id[7] = 256;
				c_id[8] = 256;
				break;
			case 2:
				c_id[5] = p->destination_ip[3];
				c_id[6] = p->destination_ip[2];
				c_id[7] = 256;
				c_id[8] = 256;
				break;
			case 3:
				c_id[5] = p->destination_ip[3];
				c_id[6] = p->destination_ip[2];
				c_id[7] = p->destination_ip[1];
				c_id[8] = 256;
				break;
			default:
				c_id[5] = p->destination_ip[3];
				c_id[6] = p->destination_ip[2];
				c_id[7] = p->destination_ip[1];
				c_id[8] = p->destination_ip[0];
				break;
			}
		}
		if (p->source_port[0] == 0 && p->source_port[1] == (unsigned int)65535) c_id[9] = 257;
		else if (p->source_port[0] == p->source_port[1] || p->source_port[0] >> 8 == p->source_port[1] >> 8)c_id[9] = p->source_port[0] >> 8;
		else c_id[9] = 256;
		if (p->destination_port[0] == 0 && p->destination_port[1] == (unsigned int)65535) c_id[10] = 257;
		else if (p->destination_port[0] == p->destination_port[1] || p->destination_port[0] >> 8 == p->destination_port[1] >> 8)c_id[10] = p->source_port[0] >> 8;
		else c_id[10] = 256;

		for (int j = 0; j < 11; j++) {
			_log[j][c_id[j]]++;
		}
	}

	FILE* fp = NULL;
	fp = fopen("analyse_data.txt", "w");
	fprintf(fp, "0 ");
	for (int j = 0; j < 5; j++)
		fprintf(fp, "%d ", _log[0][j]);
	fprintf(fp, "\n");
	for (int i = 1; i < 11; i++) {
		fprintf(fp, "%d ", i);
		for (int j = 0; j < 258; j++)
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
	printf("%lu B\n", mem);
	double res = (double)mem / 1048576.0;
	return res;
}
