#define CFG_FILE  "/jffs/etc/evasi0n.conf"	/* 配置文件 */

#define D_DHCPMODE			0	/* 默认DHCP模式 */
#define D_DAEMONMODE			0	/* 默认不后台运行 */
#define D_DHCPSCRIPT  "dhclient"	/* 默认DHCP脚本 */



#define NOT_COMMENT(c)	(c!=';' && c!='#')	/* 不是注释行 */

char *loadFile(const char *fileName);																//使用fread读入文件到内存
int arg_analyst(int argc, char **argv);														//读取命令行参数来初始化
static void findLine(const char *buf, int reStart, int *lineStart, int *lineEnd);					//寻找配置文件中的行
static int findField(const char *buf, int reStart);													//寻找配置文件中的字段
static int findKey(const char *buf, const char *field, const char *key,
	int *fieldStart, int *valueStart, unsigned long *valueSize);									//寻找配置文件中的关键词
int getValue(const char *buf, const char *field, const char *key,
	const char *defaultValue, char *value, unsigned long size);										//获得配置文件中关键词的值
int getInt(const char *buf, const char *section, const char *key, int defaultValue);				//获得配置文件中关键词的整型值
void setValue(char **buf, const char *field, const char *key, const char *value);					//设置配置文件中关键词的值
void setInt(char **buf, const char *section, const char *key, int value);							//设置配置文件中关键词的整型值
int saveFile(const char *buf, const char *fileName);												//保存文件
int cfgfile_analyst();																		//读取配置文件来初始化
void saveConfig();																			//保存参数
