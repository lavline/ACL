#include "read.h"

void read_rules(const char* file_name, ACL_rules* rules)
{
	FILE* fp = NULL;
	fp = fopen(file_name, "r");
	unsigned int sIp[5];
	unsigned int dIp[5];
	unsigned int sPort[2];
	unsigned int dPort[2];
	unsigned int protocol;
	int i = 0;
	while (fscanf(fp, "@%u.%u.%u.%u/%u\t%u.%u.%u.%u/%u\t%u : %u\t%u : %u\t%x/%*x\t%*x/%*x\t\n", &sIp[0], &sIp[1], &sIp[2], &sIp[3], &sIp[4],
		&dIp[0], &dIp[1], &dIp[2], &dIp[3], &dIp[4], &sPort[0], &sPort[1], &dPort[0], &dPort[1], &protocol) != EOF) {
		//printf("@%u.%u.%u.%u/%u\t%u.%u.%u.%u/%u\t%u : %u\t%u : %u\t0x%02x\n", sIp[0], sIp[1], sIp[2], sIp[3], sIp[4], dIp[0], dIp[1], dIp[2], dIp[3], dIp[4], sPort[0], sPort[1], dPort[0], dPort[1], protocol);
		rule r;
		r.PRI = i;
		r.protocol = (unsigned short)protocol;
		r.source_mask = (unsigned char)sIp[4];
		r.destination_mask = (unsigned char)dIp[4];
		int k = 4;
		for (int j = 0; j < 4; j++) {
			r.source_ip[j] = (unsigned char)sIp[--k];
			r.destination_ip[j] = (unsigned char)dIp[k];
		}
		//r.source_ip = sIp[0] << 24 | sIp[1] << 16 | sIp[2] << 8 | sIp[3];
		//r.destination_ip = dIp[0] << 24 | dIp[1] << 16 | dIp[2] << 8 | dIp[3];
		r.source_port[0] = (unsigned short)sPort[0]; r.source_port[1] = (unsigned short)sPort[1];
		r.destination_port[0] = (unsigned short)dPort[0]; r.destination_port[1] = (unsigned short)dPort[1];
		add_rule(rules, &r);
		i++;
	}
	fclose(fp);
}
