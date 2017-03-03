#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>

//#include<pcap.h>



#include<errno.h>
#include<ctype.h>

#ifdef WIN32

	#include<Packet32.h>
	#include<winsock.h>
	#include<WinSock2.h>

//---------------------------

	#pragma comment(lib,"wpcap.lib")
	#pragma comment(lib,"Packet.lib")
	#pragma comment(lib,"Ws2_32.lib")
	#pragma comment(lib,"libiconv.lib")
	#pragma comment(lib,"getopt.lib")


#else

	#include <sys/types.h>
	#include <sys/socket.h>
	#include <sys/ioctl.h>
	#include <sys/stat.h>

	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <net/if.h>
	#include <net/ethernet.h>

#ifdef MAC_OS
	//------BSD/Apple MacOS
	#include <net/if_var.h>
	#include <net/if_dl.h>
	#include <net/if_types.h>
#endif

#endif

#include "md5.h"


//--------802.1X Evasi0n 版本号---------

#define Evasi0n_VER "0.9 Alpha"

//--------Bug Report Address-----------

#define BUGREPORT "http://code.google.com/p/evasi0n/issues/list/"

//--------Notification Start Flag---------

#define NOTIFICATION_START_FLAG 0x12

#define MAX_PATH_SIZE			255	/* FILENAME_MAX */

//----------EAPoL报文结构体（Ethernet Header）---------
typedef struct eva_ether_header {
	u_int8_t dst_addr[6];		//目标MAC地址
	u_int8_t src_addr[6];		//源MAC地址
	u_int16_t eapol_type;		//协议类型（802.1X Authentication默认为0x888e）
}ethhdr_t;


//----------EAP报文头部结构体----------------
typedef struct eap_header{
	u_int8_t eapol_ver;			//协议版本（默认为0x01表示802.1X-2001）
	u_int8_t eap_type;			//报文类型（0x00表示EAP-Packet;0x01表示EAP-Start;0x02表示EAP-Logoff）
	u_int16_t frame_len;		//帧长度
}eaphdr_t;


//---------EAP报文的类型信息结构体------------
typedef struct eap_info{
	u_int8_t eap_code;			//EAP-Code即EAP通讯类型.在神州数码中，
								//0x01表示EAP-Request
								//0x02表示EAP-Response
								//0x03表示EAP_Success
								//0x04表示EAP-Failure.

	u_int8_t eap_id;			//EAP-ID是EAP通讯ID，通常由服务器发来的报文指定，在连续的报文内使用此ID来协商
								//或用来计算MD5-Challenge的数据.应答报文中的ID必须与请求报文中的ID相对应.

	u_int16_t data_len;			//EAP（有效）数据长度，在没有DCBA_Tail时与frame_len一致.

	u_int8_t eap_ngtn_type;		//EAP_Negotiation_Type，即EAP协商类型.
								//0x01表示EAP-Identity
								//0x02表示EAP-MD5-Challenge
								//0xfa表示EAP-Keep_Alive
}eapinfo_t;

//--------神州数码特有的DCBA-Tail结构体-----------
typedef struct dcba_tail{
	//u_char dhcp_flag;			//DHCP标志
	u_int32_t dcba_ip;			//本地IP地址
	u_int32_t dcba_mask;		//本地子网掩码
	u_int32_t dcba_gateway;		//本地网关
	u_int32_t dns_server;		//DNS服务器（一般为0.0.0.0）
	u_int8_t usr_md5[16];		//用户名（学号）的MD5值
	u_char client_ver[13];		//神州数码客户端版本（目前版本为3.5.10.0414fk）
								//Keep_Alive包中则省略了版本号的内容.
								//故使用memcpy时，应将长度减去13.
}dcba_t;




enum  EAPType {
	EAPOL_START,
	EAPOL_LOGOFF,
	EAP_REQUEST_IDENTITY,
	EAP_RESPONSE_IDENTITY,
	EAP_REQUEST_KEEP_ALIVE,
	EAP_RESPONSE_KEEP_ALIVE,
	EAP_REQUEST_MD5_CHALLENGE,
	EAP_RESPONSE_MD5_CHALLENGE,
	EAP_SUCCESS,
	EAP_FAILURE,
	UnKnown
};

enum STATE {
	READY,
	STARTED,
	ID_AUTHED,
	ONLINE
};



void show_instructions();
int evasi0n_initialize();
enum EAPType evasi0n_analyst(u_char *param, const struct pcap_pkthdr *pcap_header, const u_char *pkt_content);
u_char *evasi0n_creator(enum EAPType actionType, u_char *param, const struct pcap_pkthdr *pcap_header, const u_char *pkt_content);
u_char *get_message_digest(u_char *source, size_t md5_size);
u_char *attach_key_processor(const u_char *pkt_content, enum EAPType keyType);
int findAdaptor();
int getAdaptorMacAddress();
int printUserInfo();
int pcap_initialize();
int evasi0n_login_guide();
int evasi0n_initialize();
char *evasi0n_gbk2utf(char *gbksrc,size_t gbklen);
int evasi0n_info_extractor(const struct pcap_pkthdr *pcap_header, const u_char *pkt_content);
int evasi0n_excutive(u_char *param, const struct pcap_pkthdr *pcap_header, const u_char *pkt_content);
int evasi0n_starter();
void evasi0n_terminator();

