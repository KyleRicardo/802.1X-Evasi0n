#define NO_NOTIFY
#define NO_DYLOAD

#include "dyload.h"
#include "evasi0n.h"
#include "myconf.h"
#include "mylock.h"
#include "strnormalize.h"



/*=============Pcap相关的全局变量================*/
pcap_t *hPcap = NULL;
pcap_if_t *alldevs, *d;
char errbuf[PCAP_ERRBUF_SIZE];
u_char *pktbuf = NULL;
size_t pktlen;
/*===============================================*/


/*==============用户信息相关的全局变量=================*/
char username[16];
u_char usr_md5[16];
char password[16];
u_char *pwd_md5;
char nic[32] = "";
unsigned dhcpMode = D_DHCPMODE;	/* DHCP模式 */
char dhcpScript[64] = D_DHCPSCRIPT;/*DHCP脚本*/
unsigned daemonMode = D_DAEMONMODE;/*后台运行模式*/

u_int8_t multicast_addr[ETHER_ADDR_LEN] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };	//802.1X默认分配的多播地址
u_int8_t local_mac[ETHER_ADDR_LEN];
#ifndef NO_NOTIFY
#define D_SHOWNOTIFY		5	/* 默认Show Notify模式 */
int showNotify = D_SHOWNOTIFY;	/* 显示通知 */
#endif
/*=====================================================*/

/*===============DCBA信息相关全局变量==================*/
u_int32_t local_ip;
u_int32_t local_mask;
u_int32_t local_gateway;
u_int32_t local_dns = 0x00;
u_char client_ver[] = "3.5.10.0414fk";
/*=====================================================*/

/*================静态IP下由用户指定的地址全局变量===========*/
u_int32_t user_ip;
u_int32_t user_mask;
u_int32_t user_gateway;
u_int32_t user_dns;
/*===========================================================*/

/*===============用于锁文件和配置文件的全局变量==============*/
int lockfd;
int exitFlag;
int saveFlag;
/*===========================================================*/

enum STATE program_state;





/*
**==========================================================================

	Function Name:				show_instructions
	Type of Return Value :		void
	Type of Parameter :			void
	Description :				To show the usage of evasi0n in detail.

**==========================================================================
*/

void show_instructions()
{
	int src_len, dst_len;
	char *ins_dst;
	char *ins_src =
		"  使用方法:\n\tevasi0n [-选项] [参数]  注意:选项和参数之间有空格.\n\n"
		"  参数说明:\n"
		"\t-h,-?,--help	显示此帮助\n"
		"\t-k		在后台运行模式时候，使用此命令来退出程序\n\n"

		"\t-u username	指定用户名\n"
		"\t-p password	指定密码\n"
		"\t--device nic	指定网卡设备\n\n"

		"\t--dhcp		使用DHCP模式，在此模式下，不需要指定绑定IP和掩码\n\n"

		"\t-b		认证成功后，自动以后台模式运行（默认不使用后台模式）\n\n"

		"\t-s		保存或更新认证参数到配置文件\n\n"

		"  请保证程序以root权限运行！\n\n";
	
	//src_len = strlen(ins_src);
	//dst_len = src_len * 2;
	//ins_dst = (char *)malloc(dst_len);
	//evasi0n_transcoder("gbk", "utf-8", ins_src, src_len, ins_dst, dst_len);

	fprintf(stdout,"%s",ins_src);

}

/*
**==========================================================================

Function Name :				get_message_digest
Type of Return Value :		u_char *	----	digested message
Type of Parameter :			u_char *	----	message source
							size_t		----	length of MD5 source
Description :				To obtain the necessary MD5 value in the
							response package of MD5_Challenge.

**==========================================================================
*/

u_char *get_message_digest(u_char *source, size_t src_len)
{
	static md5_byte_t digest[16];
	md5_state_t state;
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)source, src_len);
	md5_finish(&state, digest);

	return (u_char *)digest;
}

/*
**==========================================================================

Function Name :			attach_key_processor
Type of Return Value :	u_char *		----	processed MD5 source
Type of Parameter :		const u_char *	----	raw captured packet
Description :			To retrieve the attach_key,and mix it with
						EAP_ID and username to obtain the MD5 source,
						then get it calculated and return the MD5 value.

**==========================================================================
*/

u_char *attach_key_processor(const u_char *pkt_content, enum EAPType keyType)
{
	u_char *md5_src = NULL;
	u_char *attach_key;

	if (keyType == EAP_REQUEST_MD5_CHALLENGE)
	{
		md5_src = (u_char *)malloc(1 + strlen(password) + 16);
		md5_src[0] = ((eapinfo_t *)(pkt_content + sizeof(ethhdr_t)+sizeof(eaphdr_t)))->eap_id;
		memcpy(md5_src + 1, password, strlen(password));
		attach_key = pkt_content + sizeof(ethhdr_t) + sizeof(eaphdr_t)+5+1;
		memcpy(md5_src + 1 + strlen(password), attach_key, 16);

		pwd_md5 = (u_char *)malloc(16);
		memset(pwd_md5, 0x00, 16);
		memcpy(pwd_md5, get_message_digest(md5_src, 1 + strlen(password) + 16), 16);
	}

	if (keyType == EAP_REQUEST_KEEP_ALIVE)
	{
		md5_src = (u_char *)malloc(strlen(username) + 4);
		memcpy(md5_src, username, strlen(username));
		attach_key = pkt_content + sizeof(ethhdr_t)+sizeof(eaphdr_t)+5;
		memcpy(md5_src + strlen(username), attach_key, 4);

		pwd_md5 = (u_char *)malloc(16);
		memset(pwd_md5, 0x00, 16);
		memcpy(pwd_md5, get_message_digest(md5_src, strlen(username) + 4), 16);
	}

	free(md5_src);

	return pwd_md5;
}


/*
**==========================================================================

Function Name :			findAdaptor
Type of Return Value :	int			----	status of the function
Type of Parameter :		void
Description :			To get the list of network adaptors and let the
						user to select one.

**==========================================================================
*/

int findAdaptor()
{

	int devnum, i = 0;

	//-------查找设备-------
	if (pcap_findalldevs(&alldevs, errbuf) == -1) 
	{
		fprintf(stderr, "Evasi0n!!FATAL ERROR:Finding network adaptors failed.%s\n",errbuf);
		return -2;
	}

	if(nic[0]!='\0')
	{
		for (d = alldevs; d; d = d->next)
		{
			if(strcmp(nic,d->name)==0)
				return 0;
		}
		fprintf(stderr,"Evasi0n!!Adaptor %s not found!You can select a device from the following list:\n",nic);
	}
	else
		saveFlag=1;
	

	//------列出设备--------
	printf("You have the following devices:\n\n");

	for (d = alldevs; d; d = d->next)
	{
		printf("\t[%d] %s\n", ++i, d->name);
		if (d->description)
			printf("\t(%s)\n", d->description);
		else
			printf("\t(No extra descriptions.)\n");
	}

	//------找不到设备--------

	if (i == 0)
	{
		fprintf(stderr, "\nNo interfaces found!\n");
		return -1;
	}

	//------选择设备--------

	printf("\nChoose a device(1-%d):", i);
	scanf("%d", &devnum);

	while (devnum<1 || devnum>i)
	{
		printf("\nEvasion!!The number is out of range!\n"
			"\tPlease input again(1-%d):", i);
		scanf("%d", &devnum);
	}

	for (d = alldevs, i = 1; i < devnum; d = d->next, i++);

	printf("\nEvasion>>Network Adaptor[%d] has been selected.\n", i);

	strcpy(nic,d->name);

	return 0;
}

/*
**==========================================================================

Function Name :			getAdaptorMacAddress
Type of Return Value :	int			----	status of the function
Type of Parameter :		void
Description :			To get the Mac Adrress of the selected adaptor.

**==========================================================================
*/

int getAdaptorMacAddress()
{

#ifdef WIN32
	LPADAPTER lpAdapter = 0;
	DWORD		dwErrorCode;
	PPACKET_OID_DATA  OidData;
	BOOLEAN		Status;

	//===============Get Pysical MAC Address================

	lpAdapter = PacketOpenAdapter(nic);

	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		dwErrorCode = GetLastError();
		printf("Evasi0n!!Unable to open the adapter, Error Code : %lx\n", dwErrorCode);

		return -1;
	}


	//----------Allocate a buffer to get the MAC address-------------


	OidData = malloc(6 + sizeof(PACKET_OID_DATA));

	if (OidData == NULL)
	{
		printf("Evasi0n!!FATAL ERROR:Error allocating memory!\n");
		PacketCloseAdapter(lpAdapter);
		return -1;
	}


	// -----------Retrieve the adapter MAC querying the NIC driver-------

	OidData->Oid = OID_802_3_CURRENT_ADDRESS;

	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);

	Status = PacketRequest(lpAdapter, FALSE, OidData);
	if (Status)
	{
		memcpy(local_mac, OidData->Data, ETHER_ADDR_LEN);
	}
	else
	{
		printf("Evasi0n!!NONFATAL ERROR:Failed to  retrieve the MAC address of the adapter!\n");
	}

	free(OidData);
	PacketCloseAdapter(lpAdapter);

	return 0;

#endif

#ifndef WIN32
	struct ifreq ifr;
	int sock;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Evasi0n!!FATAL ERROR:Socket open error!");
		return -1;
	}
	strcpy(ifr.ifr_name, nic);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror("Evasi0n!!FATAL ERROR:ioctl error!");
		return -1;
	}

	memcpy(local_mac, (u_char *)ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

	close(sock);

	return 0;

#endif
}


/*
**==========================================================================

Function Name :			printUserInfo
Type of Return Value :	int			----	status of the function
Type of Parameter :		void
Description :			To show the user's custom information in detail.

**==========================================================================
*/

int printUserInfo()
{
	char buf[16];
	pcap_addr_t *addrs;

	//-------------Get IP Address and Subnet Mask---------------

	for (addrs = d->addresses; addrs; addrs = addrs->next)
	{
		if (addrs->addr->sa_family == AF_INET)
		{
			local_ip = ((struct sockaddr_in *)addrs->addr)->sin_addr.s_addr;
			local_mask = ((struct sockaddr_in *)addrs->netmask)->sin_addr.s_addr;
		}
	}

	local_gateway = local_ip & local_mask;
	((u_char *)&local_gateway)[3] = 0x01;

	local_dns = 0x00;

	printf("Evasi0n>>Your custom information in detail:\n\n");

	printf("\tUsername:			%s\n", username);

	/*============输出网卡基本信息==============*/

	//Name
	printf("\tAdaptorName:			%s\n", nic);

	//Description
	printf("\tAdaptorDescription:		%s\n", d->description);

	//Loopback
	printf("\tLoopback:			%s\n", (d->flags & PCAP_IF_LOOPBACK) ? "Yes" : "No");

	//======输出MAC地址，IP地址，子网掩码，网关和DNS服务器========

	printf("\tMAC Address:			%02x:%02x:%02x:%02x:%02x:%02x\n",
		local_mac[0],
		local_mac[1],
		local_mac[2],
		local_mac[3],
		local_mac[4],
		local_mac[5]);

	printf("\tIP Address:			%s\n", inet_ntop(AF_INET, &local_ip, buf, 16));

	printf("\tSubnet Mask:			%s\n", inet_ntop(AF_INET, &local_mask, buf, 16));

	printf("\tGateway:			%s\n", inet_ntop(AF_INET, &local_gateway, buf, 16));

	printf("\tDNS Server:			%s\n", inet_ntop(AF_INET, &local_dns, buf, 16));

	//==============================================================

	printf("\tDHCP Mode:			%s\n", (dhcpMode ? "Yes" : "No(Default)"));

	printf("\tDaemon Mode:			%s\n", (daemonMode ? "Yes" : "No(Default)"));

	printf("\n");

	return 0;
}


/*
**==========================================================================

Function Name :			pcap_initialize
Type of Return Value :	int			----	status of the function
Type of Parameter :		void
Description :			Initialize the working environment of Pcap,including
						open Pcap and set the 802.1X packet filter.

**==========================================================================
*/

int pcap_initialize()
{
	bpf_u_int32 netp, maskp;
	int look_retn;
	char eva_fexp[64];
	struct bpf_program eva_fcode;

	look_retn = pcap_lookupnet(nic, &netp, &maskp, errbuf);

	if (look_retn == -1)
	{
		fprintf(stderr, "Evasi0n!!NONFATAL ERROR:Look up netp failed.%s\n"
			"\tSet it as 0xffffffff as default.\n", errbuf);
		netp = 0xffffffff;
	}

	hPcap = pcap_open_live(nic, BUFSIZ, 1, 5, errbuf);		//pcap开始工作

	if (hPcap == NULL)
	{
		fprintf(stderr, "Evasi0n!!FATAL ERROR:Pcap open failed.%s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(hPcap) != DLT_EN10MB)					//判断pcap是否在以太网下工作
	{
		fprintf(stderr, "Evasi0n!!%s is not an Ethernet.\n", nic);
		return -1;
	}

	sprintf(eva_fexp, "ether dst %02x:%02x:%02x:%02x:%02x:%02x"			//设置过滤器字符串
		" and ether proto 0x888e",
		local_mac[0], local_mac[1],
		local_mac[2], local_mac[3],
		local_mac[4], local_mac[5]);

	if (pcap_compile(hPcap, &eva_fcode, eva_fexp, 0, netp) == -1)		//编译过滤器
	{
		fprintf(stderr, "Evasi0n!!FATAL ERROR:Failed to compile the filter.%s\n",pcap_geterr(hPcap));
		return -1;
	}
	if (pcap_setfilter(hPcap, &eva_fcode) == -1)						//应用过滤器
	{
		fprintf(stderr, "Evasi0n!!FATAL ERROR:Failed to apply the filter.%s\n", pcap_geterr(hPcap));
		return -1;
	}

	pcap_freecode(&eva_fcode);
	pcap_freealldevs(alldevs);

	return 0;
}


/*
**==========================================================================

Function Name :			evasi0n_login_guide
Type of Return Value :	int			----	status of the function
Type of Parameter :		void
Description :			To get the user's information step by step if
						the config file and command line arguments
						don't work at this time.

**==========================================================================
*/

int evasi0n_login_guide()
{

	if (username[0] == '\0' || password[0] == '\0')	/* 未写用户名或密码？ */
	{
		saveFlag = 1;
		printf("Evasi0n?? Please enter your username:");
		scanf("%s", username);
		//通过stdin来无回显地读入密码
		printf("Evasi0n?? Please enter your password:");
/*
		fgets(password, sizeof(password), stdin);
		printf("\n");
		char *lEnd;
		if ((lEnd = strrchr(password, '\n')))
			*lEnd = '\0';
*/
		scanf("%s",password);
	}


	if (findAdaptor() != 0) 	/* 找不到网卡？ */
		exit(EXIT_FAILURE);

	if (getAdaptorMacAddress() == -1)
		exit(EXIT_FAILURE);

	if (dhcpMode == 0)
	{
		saveFlag = 1;
		printf("Evasi0n??Don't you use DHCP?(0-Don't use 1-Use):");
		scanf("%d", &dhcpMode);
	}

	printUserInfo();

	if (pcap_initialize() == -1)
	{
		exit(EXIT_FAILURE);
	}

	memcpy(usr_md5, get_message_digest(username, strlen(username)), 16);

	if (saveFlag == 1)
		saveConfig();

	return 0;

}


/*
**==========================================================================

Function Name :			evasi0n_initialize
Type of Return Value :	int			----	status of the function
Type of Parameter :		void
Description :			To initialize the working environment of evasi0n,
						read the arguments from config file or the user,
						load the dependent dynamic library and show logo.

**==========================================================================
*/

int evasi0n_initialize()
{
	printf("Evasi0n>>Evasi0n is initializing...");

	//在此处动态载入libpcap和libnotify
#ifndef NO_DYLOAD
	if (load_libpcap() == -1) {
#ifndef NO_NOTIFY
		if (showNotify)
			show_notify("Evasi0n - 错误提示", "载入libpcap失败, 请检查该库文件！");
#endif
		exit(EXIT_FAILURE);
	}
#endif
#ifndef NO_NOTIFY
	if (showNotify) {
		seteuid(getuid());
		if (load_libnotify() == -1)
			showNotify = 0;
		else
			set_timeout(1000 * showNotify);
		seteuid(0);
	}
#endif


	printf("Done.\n\n");

	printf("--------------------------------------------------------------------""\n"
		"   _________                                ______""\n"
		"  |  _______|                          __  /  __  \\""\n"
		" 8| |                                 (__)/  /  \\  \\""\n"
		" 0| |_________      ______ _  ________ __(  |    | |_ ____""\n"
		" 2|  ________ \\    / / __ ` |/ ______/|  |  |    | | '____`\\""\n"
		" .| |        \\ \\  / / /  \\  |\\_\\_____ |  |  |    | | |    | |""\n"
		" 1| |_______  \\ \\/ /\\ \\__/  | _____\\ \\|  |\\  \\__/  | |    | |""\n"
		" X|_________|  \\__/  \\____,_|\\_______/|__| \\______/|_|    |_|""\n\n"
		"  Welcome to Evasi0n ver %s\n\t -- A perfect solution for 802.1X authentication.\n\n"
		"  Copyright(C) 2014-2015 Kyle Ricardo<shaoyz714@126.com>\n\n"
		"  Bug Report : %s\n\n"
		"--------------------------------------------------------------------""\n", Evasi0n_VER, BUGREPORT);

	return 0;

}

/*
**==========================================================================

Function Name :			evasi0n_analyst
Type of Return Value :	enum EAPType	----	type of the packet
Type of Parameter :		void
Description :			To analyze the captured packet, obtain the
						type, so that evais0n can take the next step.

**==========================================================================
*/

enum EAPType evasi0n_analyst(u_char *param, const struct pcap_pkthdr *pcap_header, const u_char *pkt_content)
{
	ethhdr_t *etherhdr = (ethhdr_t *)pkt_content;
	eaphdr_t *eaphdr = (eaphdr_t *)(pkt_content + sizeof(ethhdr_t));
	switch (eaphdr->eap_type)
	{
		case 0x01:						//其实在这里0x01和0x02放在这个分析函数中比较多余，因为服务器请求的报文中,
			return EAPOL_START;			//这个字节必然为0x00代表EAP-Packet，不会是START和LOGOFF报文.
			break;						//后期可能考虑直接把这个switch去掉.
		case 0x02:
			return EAPOL_LOGOFF;
			break;
		case 0x00:
		{
			eapinfo_t *eapinfo = (eapinfo_t *)(pkt_content + sizeof(ethhdr_t) + sizeof(eaphdr_t));
			switch (eapinfo->eap_code)
			{
				case 0x01:
				{
					switch (eapinfo->eap_ngtn_type)
					{
						case 0x01:
							return EAP_REQUEST_IDENTITY;
							break;
						case 0x04:
							return EAP_REQUEST_MD5_CHALLENGE;
							break;
						case 0xfa:
							return EAP_REQUEST_KEEP_ALIVE;
							break;
						default:
							return UnKnown;
							break;
					}
				}													//所以在这里就不考虑0x02的情况了.
																	//因为服务器发送的不可能为Response报文.
				 case 0x03:
					 return EAP_SUCCESS;
					 break;
				 case 0x04:
					 return EAP_FAILURE;
					 break;
				 default:
					 return UnKnown;
					 break;
			}
		}
		default:
			return UnKnown;
			break;
	}
}

/*
**==========================================================================

Function Name :			evasi0n_creator
Type of Return Value :	int			----	status of the function
Type of Parameter :		void
Description :			To create the response package according to the
						analysis before.

**==========================================================================
*/

u_char *evasi0n_creator(enum EAPType actionType, u_char *param, const struct pcap_pkthdr *pcap_header, const u_char *pkt_content)
{
	u_int8_t dcbaBuf[46];
	dcba_t *dcbaTail;
	ethhdr_t *etherhdr;
	eaphdr_t *eaphdr;
	eapinfo_t *eapinfo;
	
	if (actionType != EAPOL_START && actionType != EAPOL_LOGOFF){
		dcbaBuf[0] = 0x01;
		dcbaTail = dcbaBuf + 1;
		dcbaTail->dcba_ip = local_ip;
		dcbaTail->dcba_mask = local_mask;
		dcbaTail->dcba_gateway = local_gateway;
		dcbaTail->dns_server = local_dns;
		memcpy(dcbaTail->usr_md5, usr_md5, 16);
		memcpy(dcbaTail->client_ver, client_ver, 13);
	}

	switch (actionType)
	{
	case EAPOL_START:
		pktlen = sizeof(ethhdr_t)+sizeof(eaphdr_t);
		pktbuf = (u_char *)malloc(pktlen);
		memset(pktbuf, 0x00, pktlen);

		etherhdr = (ethhdr_t *)pktbuf;
		memcpy(etherhdr->dst_addr, multicast_addr, ETHER_ADDR_LEN);
		memcpy(etherhdr->src_addr, local_mac, ETHER_ADDR_LEN);
		etherhdr->eapol_type = htons(0x888e);

		eaphdr = (eaphdr_t *)(pktbuf + sizeof(ethhdr_t));
		eaphdr->eapol_ver = 0x01;
		eaphdr->eap_type = 0x01;
		eaphdr->frame_len = 0x00;

		return pktbuf;
		break;

	case EAP_REQUEST_IDENTITY:
		pktlen = 14 + 4 + 5 + strlen(username) + 46;
		pktbuf = (u_char *)malloc(pktlen);
		memset(pktbuf, 0x00, pktlen);

		etherhdr = (ethhdr_t *)pktbuf;
		memcpy(etherhdr->dst_addr, multicast_addr, ETHER_ADDR_LEN);
		memcpy(etherhdr->src_addr, local_mac, ETHER_ADDR_LEN);
		etherhdr->eapol_type = htons(0x888e);
		
		eaphdr = (eaphdr_t *)(pktbuf + 14);
		eaphdr->eapol_ver = 0x01;
		eaphdr->eap_type = 0x00;
		eaphdr->frame_len = htons(5 + strlen(username) + 46);

		eapinfo = (eapinfo_t *)(pktbuf + 14 + 4);
		eapinfo->eap_code = 0x02;
		eapinfo->eap_id = ((eapinfo_t *)(pkt_content + 14 + 4))->eap_id;
		eapinfo->data_len = htons(5 + strlen(username));
		eapinfo->eap_ngtn_type = 0x01;

		memcpy(pktbuf + 14+4+5, username , strlen(username));

		memcpy(pktbuf + 14+4+5+strlen(username), dcbaBuf, 46);

		return pktbuf;
		break;

	case EAP_REQUEST_MD5_CHALLENGE:
		pktlen = sizeof(ethhdr_t)+sizeof(eaphdr_t)+5 + 1 + 16 + 0x80 + 46;
		pktbuf = (u_char *)malloc(pktlen);
		memset(pktbuf, 0x00, pktlen);

		etherhdr = (ethhdr_t *)pktbuf;
		memcpy(etherhdr->dst_addr, multicast_addr, ETHER_ADDR_LEN);
		memcpy(etherhdr->src_addr, local_mac, ETHER_ADDR_LEN);
		etherhdr->eapol_type = htons(0x888e);

		eaphdr = (eaphdr_t *)(pktbuf + sizeof(ethhdr_t));
		eaphdr->eapol_ver = 0x01;
		eaphdr->eap_type = 0x00;
		eaphdr->frame_len = htons(5 + 1 + 16 + 0x80 + 46);

		eapinfo = (eapinfo_t *)(pktbuf + sizeof(ethhdr_t)+sizeof(eaphdr_t));
		eapinfo->eap_code = 0x02;
		eapinfo->eap_id = ((eapinfo_t *)(pkt_content + sizeof(ethhdr_t)+sizeof(eaphdr_t)))->eap_id;
		eapinfo->data_len = htons(5 + 1 + 16 + 0x80);
		eapinfo->eap_ngtn_type = 0x04;

		pktbuf[sizeof(ethhdr_t)+sizeof(eaphdr_t)+5] = 0x10;
		attach_key_processor(pkt_content, EAP_REQUEST_MD5_CHALLENGE);
		memcpy(pktbuf + sizeof(ethhdr_t)+sizeof(eaphdr_t)+5+1, pwd_md5, 16);

		memcpy(pktbuf + sizeof(ethhdr_t)+sizeof(eaphdr_t)+5+1 + 16 + 0x80, dcbaBuf, 46);

		free(pwd_md5);

		return pktbuf;
		break;

	case EAP_REQUEST_KEEP_ALIVE:
		pktlen = sizeof(ethhdr_t)+sizeof(eaphdr_t) + 5 + 16 + 46-13;
		pktbuf = (u_char *)malloc(pktlen);
		memset(pktbuf, 0x00, pktlen);

		etherhdr = (ethhdr_t *)pktbuf;
		memcpy(etherhdr->dst_addr, multicast_addr, ETHER_ADDR_LEN);
		memcpy(etherhdr->src_addr, local_mac, ETHER_ADDR_LEN);
		etherhdr->eapol_type = htons(0x888e);

		eaphdr = (eaphdr_t *)(pktbuf + sizeof(ethhdr_t));
		eaphdr->eapol_ver = 0x01;
		eaphdr->eap_type = 0x00;
		eaphdr->frame_len = htons(5 + 16 + 46 - 13);

		eapinfo = (eapinfo_t *)(pktbuf + sizeof(ethhdr_t)+sizeof(eaphdr_t));
		eapinfo->eap_code = 0x02;
		eapinfo->eap_id = ((eapinfo_t *)(pkt_content + sizeof(ethhdr_t)+sizeof(eaphdr_t)))->eap_id;
		eapinfo->data_len = htons(5 + 16);
		eapinfo->eap_ngtn_type = 0xfa;

		attach_key_processor(pkt_content, EAP_REQUEST_KEEP_ALIVE);
		memcpy(pktbuf + sizeof(ethhdr_t)+sizeof(eaphdr_t)+5, pwd_md5, 16);

		memcpy(pktbuf + sizeof(ethhdr_t)+sizeof(eaphdr_t)+5+16, dcbaBuf, 46 - 13);

		free(pwd_md5);

		return pktbuf;
		break;

	case EAPOL_LOGOFF:
		pktlen = sizeof(ethhdr_t)+sizeof(eaphdr_t);
		pktbuf = (u_char *)malloc(pktlen);
		memset(pktbuf, 0x00, pktlen);

		etherhdr = (ethhdr_t *)pktbuf;
		memcpy(etherhdr->dst_addr, multicast_addr, ETHER_ADDR_LEN);
		memcpy(etherhdr->src_addr, local_mac, ETHER_ADDR_LEN);
		etherhdr->eapol_type = htons(0x888e);

		eaphdr = (eaphdr_t *)(pktbuf + sizeof(ethhdr_t));
		eaphdr->eapol_ver = 0x01;
		eaphdr->eap_type = 0x02;
		eaphdr->frame_len = 0x00;

		return pktbuf;
		break;

	default:
		return NULL;
		break;
	}
}


/*
**==========================================================================

Function Name		:evasi0n_gbk2utf
Type of Return Value:char *			----	result of the GBK to UTF-8 convert
Type of Parameter	:char *gbksrc	----	source GBK string
					 size_t gbklen	----	length of GBK string		
Description			:To transcode the received GBK notification to UTF-8 to
					 avoid the garbled.

**==========================================================================
*/

char *evasi0n_gbk2utf(char *gbksrc,size_t gbklen)
{
    str_normalize_init();

	size_t utf8len = gbklen * 3 + 1;
	char *utf8dst = (char *)malloc(utf8len);

	memset(utf8dst,0,utf8len);
	
	char *temp=(char *)malloc(gbklen+5);
	memset(temp, 0, gbklen+5);
	memcpy(temp,gbksrc,gbklen);
	gbksrc = temp;
	gbklen = strlen(gbksrc);

	gbk_to_utf8(gbksrc, gbklen, &utf8dst, &utf8len);

	free(temp);

	return utf8dst;
}


/*
**==========================================================================

Function Name		:evasi0n_info_extractor
Type of Return Value:int			----	status of the function
Type of Parameter	:default	
Description			:To extract the notification in the EAP_SUCCESS
					 packet form server,and then print it.
					 
**==========================================================================
*/

int evasi0n_info_extractor(const struct pcap_pkthdr *pcap_header, const u_char *pkt_content)
{
	u_char *pkt_index;
	bpf_u_int32 packet_len = pcap_header->caplen;
	char *info_buf;
	u_int8_t info_length;
	size_t dst_length;

	//-----寻找并使索引指针移动到消息区域的起始位置-----

	{
		if (*(pkt_index = pkt_content + 0x2A) == NOTIFICATION_START_FLAG)
			goto EVA_INFO;

		if (packet_len < 0x42)
			return -1;
		if (*(pkt_index = pkt_content + 0x42) == NOTIFICATION_START_FLAG)
			goto EVA_INFO;

		if (packet_len < 0x9A)
			return -1;
		if (*(pkt_index = pkt_content + 0x9A) == NOTIFICATION_START_FLAG)
			goto EVA_INFO;

		if (packet_len < 0x120)
			return -1;
		if (*(pkt_index = pkt_content + 0x120) == NOTIFICATION_START_FLAG)
			goto EVA_INFO;
	}
	
	if ((*pkt_index) != NOTIFICATION_START_FLAG)
	{
		fprintf(stderr, "\nEvasi0n!!NONFATAL ERROR:Cannot get the information from server...\n");
		return -1;
	}

EVA_INFO:;

	pkt_index++;							//消息标记后紧跟的一位便是消息长度，
	info_length = *pkt_index;				//将其赋值给长度变量.
	info_length -= 2;						//(注意:此长度包含了flag和length, 将其减去.)
	pkt_index++;							//此时索引指向的是消息正文的开头.
	
	info_buf = evasi0n_gbk2utf(pkt_index, info_length);

	printf("\n    >>802.1X Evasi0n--System Notification:\n    %s\n\n", info_buf);

	free(info_buf);

	return 0;
}

/*
**==========================================================================

Function Name :			evasi0n_executive
Type of Return Value :	int			----	status of the function
Type of Parameter :		default
Description :			The callback function of pcap_loop(),to handle
						the raw packet captured by Pcap according to
						the packet type,set the authentication state,
						and take the corresponding actions.

**==========================================================================
*/

int evasi0n_excutive(u_char *param, const struct pcap_pkthdr *pcap_header, const u_char *pkt_content)
{
	enum EAPType packet_type;
#ifdef DEBUG
	packet_inspector(pkt_content,pcap_header->caplen);
#endif
	u_char *packet;
	packet_type = evasi0n_analyst(param, pcap_header, pkt_content);

	switch (packet_type)
	{
	case EAP_REQUEST_IDENTITY:
		program_state = STARTED;

		printf("Evasi0n>>Caputured a EAP_REQUEST_IDENTITY packet.\n");
		packet = evasi0n_creator(packet_type, param, pcap_header, pkt_content);
#ifdef DEBUG
		packet_inspector(pktbuf,pktlen);
#endif
		printf("Evasi0n>>Sending the corresponding EAP_RESPONSE_IDENTITY packet...");
		if (pcap_sendpacket(hPcap, packet, pktlen) == -1)
		{
			printf("Failed.\n\tCannot send the packet...%s\n", pcap_geterr(hPcap));
			free(packet);
			packet = NULL;
			return -1;
		}
		else
			printf("Done.\n");

		free(packet);
		packet = NULL;
		return 0;

	case EAP_REQUEST_MD5_CHALLENGE:
		program_state = ID_AUTHED;

		printf("Evasi0n>>Caputured a EAP_REQUEST_MD5_CHALLENGE packet.\n");
		packet = evasi0n_creator(packet_type, param, pcap_header, pkt_content);
#ifdef DEBUG
		packet_inspector(pktbuf,pktlen);
#endif
		printf("Evasi0n>>Sending the corresponding EAP_RESPONSE_MD5_CHALLENGE packet...");
		if (pcap_sendpacket(hPcap, packet, pktlen) == -1)
		{
			printf("Failed.\n\tCannot send the packet...%s\n", pcap_geterr(hPcap));
			free(packet);
			packet = NULL;
			return -1;
		}
		else
			printf("Done.\n");

		free(packet);
		packet = NULL;
		return 0;

	case EAP_REQUEST_KEEP_ALIVE:
		printf("Evasi0n>>Caputured a EAP_REQUEST_KEEP_ALIVE packet.\n");
		packet = evasi0n_creator(packet_type, param, pcap_header, pkt_content);
#ifdef DEBUG
		packet_inspector(pktbuf,pktlen);
#endif
		printf("Evasi0n>>Sending the corresponding EAP_RESPONSE_KEEP_ALIVE packet...");
		if (pcap_sendpacket(hPcap, packet, pktlen) == -1)
		{
			printf("Failed.\n\tCannot send the heartbeat packet...%s\n", pcap_geterr(hPcap));
			free(packet);
			packet = NULL;
			return -1;
		}
		else
			printf("Done.\n");

		free(packet);
		packet = NULL;
		return 0;

	case EAP_SUCCESS:
		program_state = ONLINE;

		printf("Evasi0n>>802.1X Successfully Authenticated.You have logged in the network.\n");
		printf("Evasi0n>>Enjoy~~~!\n");
		evasi0n_info_extractor(pcap_header,pkt_content);
		
		printf("Evasi0n>>Sending heartbeat packet to keep alive...\n");

		if (daemonMode){
			daemonMode = 0;
			daemon_init();
		}

		return 0;

	case EAP_FAILURE:
		if (program_state == STARTED)
		{
			printf("Evasi0n!!FATAL ERROR:Invalid username or you have insufficient balance.\n"
					"\tThe following is the notification given by server,maybe it helps:");
			evasi0n_info_extractor(pcap_header, pkt_content);
		}
		if (program_state == ID_AUTHED)
		{
			printf("Evasi0n!!FATAL ERROR:Your password and your username mismatch.Please check.\n"
					"\tThe following is the notification given by server,maybe it helps:");
			evasi0n_info_extractor(pcap_header, pkt_content);
		}
		if (program_state == ONLINE)
		{
			printf("Evasi0n!!FATAL ERROR:Forced to logoff.\n");
			evasi0n_info_extractor(pcap_header, pkt_content);
		}

		packet = evasi0n_creator(EAPOL_LOGOFF, param, pcap_header, pkt_content);
		printf("Evasi0n>>Sending the logoff packet to ensure that you have logged off...");
		if (pcap_sendpacket(hPcap, packet, pktlen) == -1)
			printf("Failed.\n\tCannot send the packet...%s\n", pcap_geterr(hPcap));
		else
			printf("Done.\n");
		free(packet);

		program_state = READY;
		pcap_breakloop(hPcap);

		return 0;

	default:
		return -1;
		break;
	}
}


/*
**==========================================================================

Function Name :			evasi0n_starter
Type of Return Value :	int			----	status of the function
Type of Parameter :		void
Description :			Use DHCP Script to renew IP and send the start
						packet to begin the authentication.	

**==========================================================================
*/

int evasi0n_starter()
{
	//if (dhcpMode)
	//	system(dhcpScript);

	printf("Evasi0n>>Sending EAPoL-Start packet to begin the authentication...");
	evasi0n_creator(EAPOL_START, NULL, NULL, NULL);
	if (pcap_sendpacket(hPcap, pktbuf, pktlen) == -1)
	{
		printf("Failed.\n\tCannot send the packet...%s\n", pcap_geterr(hPcap));
		free(pktbuf);
		pktbuf = NULL;
		return -1;
	}
	else
		printf("Done.\n");
#ifdef DEBUG
	packet_inspector(pktbuf,pktlen);
#endif
	free(pktbuf);
	pktbuf = NULL;

	pcap_loop(hPcap, -1, evasi0n_excutive, NULL);   /* main loop */

	return 0;

}


/*
**==========================================================================

Function Name :			evasi0n_terminator
Type of Return Value :	void
Type of Parameter :		void
Description :			Send the logoff packet to terminate the authentication.	

**==========================================================================
*/

void evasi0n_terminator()
{
	printf("Evasi0n>>Sending EAPoL-Logoff packet to terminate the authentication...");
	evasi0n_creator(EAPOL_LOGOFF, NULL, NULL, NULL);
	if (pcap_sendpacket(hPcap, pktbuf, pktlen) == -1)
	{
		printf("Failed.\n\tCannot send the packet...%s\n", pcap_geterr(hPcap));
		free(pktbuf);
		return;
	}
	else
		printf("Done.\n");
#ifdef DEBUG
	packet_inspector(pktbuf,pktlen);
#endif
	free(pktbuf);
	pktbuf = NULL;
	pcap_breakloop(hPcap);

}


/*
**==========================================================================

Function Name :			packet_inspector
Type of Return Value :	void
Type of Parameter :		Have explained by the name of arguments.
Description :			A debug function used to inspect the content of the
						802.1X packet.	

**==========================================================================
*/

void packet_inspector(u_char *packet_pointer,int packet_size)
{
	int i;
	if(packet_pointer != NULL){
		for(i = 0; i < packet_size; i++)
		{
			if(!(i % 16))
				printf("\n");
			printf("%02x ",packet_pointer[i]);
		}
	printf("\n");
	}
}



int main(int argc,char *argv[])
{
	int inst_pid;

	atexit(exit_handle);
	signal(SIGINT, signal_interrupted);	 /* Ctrl+C */
	signal(SIGTERM, signal_interrupted);	/* 被结束时 */
	signal(SIGSTOP, signal_interrupted);	 /* Ctrl+\ */
	signal(SIGKILL, signal_interrupted);	 /* 暴力结束时 */
	signal(SIGQUIT, signal_interrupted);	 /* Ctrl+Z */


	evasi0n_initialize();

	saveFlag = (cfgfile_analyst() == 0) ? 0 : 1;
	arg_analyst(argc, argv);

	//打开锁文件
	lockfd = open(LOCK_FILE, O_RDWR | O_CREAT, LOCKMODE);
	if (lockfd < 0){
		perror("Evasi0n!!FATAL ERROR:Open lockfile error!");
		exit(EXIT_FAILURE);
	}

	if ((inst_pid = is_Running())) {
		fprintf(stderr, "Evasi0n!!Program is already "
			"running with PID %d\n", inst_pid);
		exit(EXIT_SUCCESS);
	}

	evasi0n_login_guide();

	evasi0n_starter();

	//pcap_close(hPcap);

	return 0;

}
