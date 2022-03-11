#include "read.h"
#include "read.h"

int read_rules(const char* file_name, ACL_rules* rules)
{
	FILE* fp = NULL;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "error - can not open rules file\n");
		return 0;
	}
	unsigned int sIp[5];
	unsigned int dIp[5];
	unsigned int sPort[2];
	unsigned int dPort[2];
	unsigned int protocol[2];
	int i = 0;
	while (fscanf(fp, "@%u.%u.%u.%u/%u\t%u.%u.%u.%u/%u\t%u : %u\t%u : %u\t%x/%x\t%*x/%*x\t\n", &sIp[0], &sIp[1], &sIp[2], &sIp[3], &sIp[4],
		&dIp[0], &dIp[1], &dIp[2], &dIp[3], &dIp[4], &sPort[0], &sPort[1], &dPort[0], &dPort[1], &protocol[1], &protocol[0]) != EOF) {
		//printf("@%u.%u.%u.%u/%u\t%u.%u.%u.%u/%u\t%u : %u\t%u : %u\t0x%02x\n", sIp[0], sIp[1], sIp[2], sIp[3], sIp[4], dIp[0], dIp[1], dIp[2], dIp[3], dIp[4], sPort[0], sPort[1], dPort[0], dPort[1], protocol);
		rule r;
		r.PRI = i;
		r.protocol[0] = (unsigned char)protocol[0]; // mask
		r.protocol[1] = (unsigned char)protocol[1]; // protocol
		r.source_mask = (unsigned char)sIp[4];
		r.destination_mask = (unsigned char)dIp[4];
		int k = 4;
		for (int j = 0; j < 4; j++) {
			r.source_ip[j] = (unsigned char)sIp[--k];
			r.destination_ip[j] = (unsigned char)dIp[k];
		}
		r.source_port[0] = (unsigned short)sPort[0]; r.source_port[1] = (unsigned short)sPort[1];
		r.destination_port[0] = (unsigned short)dPort[0]; r.destination_port[1] = (unsigned short)dPort[1];
		add_rule(rules, &r);
		i++;
	}
	fclose(fp);
	return 1;
}

int read_messages(const char* file_name, ACL_messages* messages)
{
	FILE* fp = NULL;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "error - can not open trace file\n");
		return 0;
	}
	message _m = { 0 };
	unsigned int ip_src, ip_des;
	while (fscanf(fp, "%u\t%u\t%hu\t%hu\t%u\t%*u\t%*d\n", &ip_src, &ip_des, &_m.source_port, &_m.destination_port, &_m.protocol) != EOF) {
		memcpy(_m.source_ip, &ip_src, 4);
		memcpy(_m.destination_ip, &ip_des, 4);
		//printf("%u\t%u\t%u\t%u\t%u\n", ip_src, ip_des, _m.source_port, _m.destination_port, _m.protocol);
		add_message(messages, &_m);
	}
	fclose(fp);
	return 1;
}

int read_contest_rule(const char* file_name, ACL_rules* rules)
{
	FILE* fp = NULL;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "error - can not open rules file\n");
		return 0;
	}
	unsigned int sIp[5];
	unsigned int dIp[5];
	unsigned int sPort[2];
	unsigned int dPort[2];
	unsigned int protocol[2];
	unsigned int i = 0;
	while (fscanf(fp, "sip=%u.%u.%u.%u/%u,dip=%u.%u.%u.%u/%u,sport=%u:%u,dport=%u:%u,proto=%u,index=%u\n", &sIp[0], &sIp[1], &sIp[2], &sIp[3], &sIp[4],
		&dIp[0], &dIp[1], &dIp[2], &dIp[3], &dIp[4], &sPort[0], &sPort[1], &dPort[0], &dPort[1], &protocol[0], &i) != EOF) {
		//printf("@%u.%u.%u.%u/%u\t%u.%u.%u.%u/%u\t%u : %u\t%u : %u\t0x%02x\n", sIp[0], sIp[1], sIp[2], sIp[3], sIp[4], dIp[0], dIp[1], dIp[2], dIp[3], dIp[4], sPort[0], sPort[1], dPort[0], dPort[1], protocol[0]);
		rule r;
		r.PRI = i;
		if (r.protocol[1] != 0)r.protocol[0] = 0xFF; // mask
		r.protocol[1] = protocol[0]; // proto
		r.source_mask = (unsigned char)sIp[4];
		r.destination_mask = (unsigned char)dIp[4];
		int k = 4;
		for (int j = 0; j < 4; j++) {
			r.source_ip[j] = (unsigned char)sIp[--k];
			r.destination_ip[j] = (unsigned char)dIp[k];
		}
		r.source_port[0] = (unsigned short)sPort[0]; r.source_port[1] = (unsigned short)sPort[1];
		r.destination_port[0] = (unsigned short)dPort[0]; r.destination_port[1] = (unsigned short)dPort[1];
		add_rule(rules, &r);
		//i++;
	}
	fclose(fp);
	return 1;
}

int read_contest_message(const char* file_name, ACL_messages* messages)
{
	FILE* fp = NULL;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "error - can not open trace file\n");
		return 0;
	}
	message _m = { 0 };
	//unsigned int ip_src, ip_des;
	unsigned int sIp[4];
	unsigned int dIp[4];
	while (fscanf(fp, "sip=%u.%u.%u.%u,dip=%u.%u.%u.%u,sport=%hu,dport=%hu,proto=%u,index=%*u\n",
		&sIp[0], &sIp[1], &sIp[2], &sIp[3],
		&dIp[0], &dIp[1], &dIp[2], &dIp[3],
		&_m.source_port, &_m.destination_port, &_m.protocol) != EOF) {
		int k = 4;
		for (int j = 0; j < 4; j++) {
			_m.source_ip[j] = (unsigned char)sIp[--k];
			_m.destination_ip[j] = (unsigned char)dIp[k];
		}
		//memcpy(_m.source_ip, &ip_src, 4);
		//memcpy(_m.destination_ip, &ip_des, 4);
		//printf("%u\t%u\t%u\t%u\t%u\n", ip_src, ip_des, _m.source_port, _m.destination_port, _m.protocol);
		add_message(messages, &_m);
	}
	fclose(fp);
	return 1;
}