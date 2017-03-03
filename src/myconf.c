#include "myconf.h"
#include "dyload.h"
#include "evasi0n.h"

extern char username[16];
extern char password[16];
extern char nic[32];
extern unsigned dhcpMode;
extern unsigned daemonMode;
extern char dhcpScript[64];
extern int exitFlag;
extern int saveFlag;
extern u_int32_t user_ip;
extern u_int32_t user_mask;
extern u_int32_t user_gateway;
extern u_int32_t user_dns;

#ifndef strnicmp
#define strnicmp strncasecmp
#endif

int arg_analyst(int argc,char **argv)
{
	char *str, c;
	int i;
	for (i = 1; i < argc; i++)
	{
		str = argv[i];
		if (str[0] != '-' && str[0] != '/')
			continue;
		c = str[1];
		if (c == 'h' || c == '?' || strcmp(str, "--help") == 0){
			show_instructions();
			exit(EXIT_SUCCESS);
		}
		if (strcmp(str, "--device") == 0)
		{
			if(++i < argc)
				str = argv[i];
			else
			{
				fprintf(stderr, "Evasi0n!!FATAL ERROR:The option --device requires an argument!\n");
				exit(EXIT_FAILURE);
			}
			if (str[0] == '-' || str[0] == '/')
			{
				fprintf(stderr, "Evasi0n!!FATAL ERROR:The option --device requires an argument!\n");
				exit(EXIT_FAILURE);
			}
			strncpy(nic, argv[i], sizeof(nic)-1);
			continue;
		}

		if (strcmp(str, "--dhcp") == 0){
			dhcpMode = 1;
			continue;
		}
		switch (c)
		{
		case 'k':
			exitFlag = 1;
			return 0;
		case 'u':
			if(++i < argc)
				str = argv[i];
			else
			{
				fprintf(stderr, "Evasi0n!!FATAL ERROR:The option -u requires an argument!\n");
				exit(EXIT_FAILURE);
			}
			if (str[0] == '-' || str[0] == '/')
			{
				fprintf(stderr, "Evasi0n!!FATAL ERROR:The option -u requires an argument!\n");
				exit(EXIT_FAILURE);
			}
			strncpy(username, argv[i], sizeof(username)-1);
			break;
		case 'p':
			if(++i < argc)
				str = argv[i];
			else
			{
				fprintf(stderr, "Evasi0n!!FATAL ERROR:The option -p requires an argument!\n");
				exit(EXIT_FAILURE);
			}
			if (str[0] == '-' || str[0] == '/')
			{
				fprintf(stderr, "Evasi0n!!FATAL ERROR:The option -p requires an argument!\n");
				exit(EXIT_FAILURE);
			}
			strncpy(password, argv[i], sizeof(password)-1);
			break;
		case 'b':
			daemonMode = 1;
			break;
		case 's':
			saveFlag = 1;
			break;
		default:
			fprintf(stderr, "Evasi0n!!FATAL ERROR:The option %s is invalid.Use -h or --help to show instuctions.\n", str);
			exit(EXIT_FAILURE);
			break;
		}

		
	}

	return 0;
}

char *loadFile(const char *fileName)
{
	FILE *fp = NULL;
	long size = 0;
	char *buf = NULL;
	if ((fp = fopen(fileName, "rb")) == NULL)
		return NULL;
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	rewind(fp);
	buf = (char *)malloc(size + 1);
	buf[size] = '\0';
	if (fread(buf, size, 1, fp) < 1)
	{
		free(buf);
		buf = NULL;
	}
	fclose(fp);
	return buf;
}

//寻找行首行尾的函数
static void findLine(const char *buf, int reStart, int *lineStart, int *lineEnd)
{
	int start, end;
	for (start = reStart; buf[start] == ' ' || buf[start] == '\t' || buf[start] == '\r' || buf[start] == '\n'; start++);	//去除行首空格
	for (end = start; buf[end] != '\r' && buf[end] != '\n' && buf[end] != '\0'; end++);
	*lineStart = start;
	*lineEnd = end;
}

//寻找字段的函数
static int findField(const char *buf, int reStart)
{
	int lineStart, lineEnd, i;
	for (lineEnd = reStart; buf[lineEnd] != '\0';)
	{
		findLine(buf, lineEnd, &lineStart, &lineEnd);
		if (buf[lineStart] == '[')
		{
			for (i = lineStart + 1; i<lineEnd && buf[i] != ']'; i++);
			if (i < lineEnd)
				return lineStart;
		}
	}
	return -1;
}

//寻找关键词（变量名）和及其值的函数
static int findKey(const char *buf, const char *field, const char *key,
	int *fieldStart, int *valueStart, unsigned long *valueSize)
{
	if (key == NULL)
		return -1;
	int lineStart, lineEnd, i;
	for (*fieldStart = -1, lineEnd = 0; buf[lineEnd] != '\0';)
	{
		findLine(buf, lineEnd, &lineStart, &lineEnd);
		if (buf[lineStart] == '[')
		{
			for (i = ++lineStart; i<lineEnd && buf[i] != ']'; i++);
			if (i < lineEnd && strnicmp(buf + lineStart, field, i - lineStart) == 0)
				*fieldStart = lineStart - 1;
			else
				continue;		//找不到匹配的字段就跳过寻找关键词，一直到找到匹配的字段为止
		}
		//找到匹配的字段后，才开始在对应的字段下寻找关键词
		else if (*fieldStart != -1 && NOT_COMMENT(buf[lineStart]))
		{
			for (i = lineStart; i<lineEnd && buf[i] != '='; i++);
			if (i < lineEnd && strnicmp(buf + lineStart, key, i - lineStart) == 0)
			{
				*valueStart = i + 1;
				*valueSize = lineEnd - *valueStart;
				return 0;
			}
		}
	}
	return -1;
}

//用于读取参数值的函数
int getValue(const char *buf, const char *field, const char *key,
	const char *defaultValue, char *value, unsigned long size)
{
	int fieldStart, valueStart;
	unsigned long valueSize;

	if (findKey(buf, field, key, &fieldStart, &valueStart, &valueSize) != 0 || valueSize == 0)	/* 找不到请求的关键词或找不到值 */
	{
		strncpy(value, defaultValue, size);	
		return -1;
	}
	if (size - 1 < valueSize)		/* 找到但太长？ */
		valueSize = size - 1;
	memset(value, 0, size);
	strncpy(value, buf + valueStart, valueSize);
	return 0;
}

int getInt(const char *buf, const char *section, const char *key, int defaultValue)
{
	char value[16] = { 0 };
	getValue(buf, section, key, "", value, sizeof(value));
	if (value[0] == '\0')	/* 找不到或找到但为空？ */
		return defaultValue;
	return atoi(value);
}

void setValue(char **buf, const char *field, const char *key, const char *value)
{
	int fieldStart, valueStart;
	unsigned long valueSize;
	char *newBuf = NULL;

	if (field == NULL || key == NULL)
		return;

	if (findKey(*buf, field, key, &fieldStart, &valueStart, &valueSize) == 0)	/* 如果找到关键词 */
	{
		if (value == NULL)	/* 如果value为空，则直接删除对应的关键词 */
			memmove(*buf + valueStart - strlen(key) - 1, *buf + valueStart + valueSize,
			strlen(*buf) + 1 - valueStart - valueSize);
		else	/* key不为空，则修改key为新的值 */
		{
			newBuf = (char *)malloc(strlen(*buf) - valueSize + strlen(value) + 1);		//原长度-原值长度+新值长度
			memcpy(newBuf, *buf, valueStart);											//该值之前的所有内容不变
			strcpy(newBuf + valueStart, value);											//将新值写入
			strcpy(newBuf + valueStart + strlen(value), *buf + valueStart + valueSize);	//将原值后面的内容拷贝，保持不变
			free(*buf);
			*buf = newBuf;
		}
	}
	else if (fieldStart != -1 && value != NULL)	/* 能找到字段，但找不到关键词，且value并没有为空 */
	{
			newBuf = (char *)malloc(strlen(*buf) + strlen(key) + strlen(value) + 4);
			valueSize = fieldStart + strlen(field) + 2;
			memcpy(newBuf, *buf, valueSize);
			sprintf(newBuf + valueSize, "\n%s=%s", key, value);
			strcpy(newBuf + strlen(newBuf), *buf + valueSize);
			free(*buf);
			*buf = newBuf;
	}
	else	/* 连字段都没找到 */
	{
		if (key != NULL && value != NULL)
		{
			newBuf = (char *)malloc(strlen(*buf) + strlen(field) + strlen(key) + strlen(value) + 8);
			strcpy(newBuf, *buf);
			sprintf(newBuf + strlen(newBuf), "\n[%s]\n%s=%s", field, key, value);
			free(*buf);
			*buf = newBuf;
		}
	}
}


void setInt(char **buf, const char *section, const char *key, int value)
{
	char svalue[16];
	sprintf(svalue, "%d", value);
	setValue(buf, section, key, svalue);
}

int saveFile(const char *buf, const char *fileName)
{
	FILE *fp;
	int result;

	if ((fp = fopen(fileName, "wb")) == NULL)
		return -1;
	result = fwrite(buf, strlen(buf), 1, fp)<1 ? -1 : 0;
	fclose(fp);
	return result;
}

int cfgfile_analyst()
{
	char tmp[16];
	char *buf = loadFile(CFG_FILE);
	if (buf == NULL)
		return -1;

	dhcpMode = getInt(buf, "Evasi0n", "DHCPMode", 0);
	daemonMode = getInt(buf, "Evasi0n", "DaemonMode", 0);

	getValue(buf, "Evasi0n", "Username", "", username, sizeof(username));
	getValue(buf, "Evasi0n", "Password", "", password, sizeof(password));
	getValue(buf, "Evasi0n", "Adaptor", "", nic, sizeof(nic));
	getValue(buf, "Evasi0n", "DHCPScript", D_DHCPSCRIPT, dhcpScript, sizeof(dhcpScript));

	if (dhcpMode == 0){
		getValue(buf, "Evasi0n", "IP", "255.255.255.255", tmp, sizeof(tmp));
		user_ip = inet_addr(tmp);
		getValue(buf, "Evasi0n", "Mask", "255.255.255.255", tmp, sizeof(tmp));
		user_mask = inet_addr(tmp);
		getValue(buf, "Evasi0n", "Gateway", "0.0.0.0", tmp, sizeof(tmp));
		user_gateway = inet_addr(tmp);
		getValue(buf, "Evasi0n", "DNS", "0.0.0.0", tmp, sizeof(tmp));
		user_dns = inet_addr(tmp);
	}

	free(buf);
	return 0;
}

void saveConfig()
{
	char *buf = loadFile(CFG_FILE);
	char tmp[16];
	if (buf == NULL) {
		buf = (char *)malloc(1);
		buf[0] = '\0';
	}
	setValue(&buf, "Evasi0n", "DHCPScript", dhcpScript);

	if (!dhcpMode){
		setValue(&buf, "Evasi0n", "DNS", inet_ntop(AF_INET, &user_dns, tmp, 16));
		setValue(&buf, "Evasi0n", "Gateway", inet_ntop(AF_INET, &user_gateway, tmp, 16));
		setValue(&buf, "Evasi0n", "Mask", inet_ntop(AF_INET, &user_mask, tmp, 16));
		setValue(&buf, "Evasi0n", "IP", inet_ntop(AF_INET, &user_ip, tmp, 16));
	}
	
	setValue(&buf, "Evasi0n", "Adaptor", nic);
	setValue(&buf, "Evasi0n", "Password", password);
	setValue(&buf, "Evasi0n", "Username", username);

	setInt(&buf, "Evasi0n", "DHCPMode", dhcpMode);
	setInt(&buf, "Evasi0n", "DaemonMode", daemonMode);

	if (saveFile(buf, CFG_FILE) != 0)
		printf("Evasi0n!! Failed to save configuration to %s\n", CFG_FILE);
	else
		printf("Evasi0n>>Authentication arguments have been successfully saved to %s.\n", CFG_FILE);
	free(buf);
}
