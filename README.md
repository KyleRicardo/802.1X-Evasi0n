# 802.1X Evasi0n

----

## 项目基本目标

官方神州数码客户端BUG极多，界面也并不友好，最大的弊病是其加入了多网卡检测，使用Wi-Fi共享工具建立Wi-Fi的时候它会检测到并在一段时间内强制下线。

考虑到最近智能路由的兴起，决定另辟蹊径，通过将802.1X认证客户端移植到基于Linux的路由器（OpenWrt, DD-Wrt等）中，来实现Wi-Fi共享校园网的目的。这便是本项目的基本目标。

## 项目中期目标

虽然本项目的定位为一个全新的、自由的、基于Pcap库的802.1X跨平台认证客户端，但还是应该有针对不同平台的不同特性。对于路由器和Linuxer，一个shell足以满足其需求。针对Windows平台，用shell来代替一个本来有GUI的客户端，多少有点反人类。对于那些使用Mac OS的土豪们，用shell就更称不上他们的身份了。于是就有了以下中期目标：

  * Win平台新增带有精美皮肤的Win32 Beta版本，新增一键开启Wi-Fi功能，让每个人都能愉快地享受Wi-Fi带来的乐趣。本平台中的项目可能会更名为802.1X Wire Evasi0n，其中用于认证的部分被称为Wire，用于共享Wi-Fi的部分被称为Evasi0n。

  * Mac平台新增带有GUI的Beta版本，让同学们不再为琐碎的命令行参数而烦恼，并保持Mac一贯的简洁风格。

## 项目长期目标

像爱因斯坦的统一场理论一样，人们总是想要把一切的一切归在一个框架里面——本项目也不例外。项目长期目标是将国内高校使用的802.1X认证客户端统一起来，其中包括神州数码，锐捷，赛尔，联想，华为等等。以形成一个真正的802.1X Evasi0n。

## 项目特性

### 保持前辈客户端的优点

  * 利用Pcap的循环进行驱动级别的报文过滤，极大地减少CPU占用
  * 纯C语言编写，极低的内存占用
  * 尽可能减少库的依赖，容易编译（目前仅依赖libpcap）

### 新增优势

  * 模仿锐捷客户端，新增configure文件，可以自动生成Makefile，方便编译
  * 支持在首次运行时，可以不带参数，并使用向导模式认证
  * 动态载入链接库
  * 支持配置文件的保存
  * 支持掉线重连
  * 使用中英文，并解决编码问题
  * 支持显示服务器返回的中文提示消息
  * 新增对IPv6的支持

## 鸣谢

  * Netxray前辈提供的MyStar源码
  * Pentie前辈提供的ZDCClient源码与802.1X认证流程分析
  * HustMoon前辈提供的MentoHUST源码
  * Zumikua前辈提供的武汉大学文理学部关于心跳包的Issue
  * Icelee前辈对关于OpenWrt编译与IPv6地址获取方面的贡献
  * 木丛童鞋对我长期以来的支持和关注
  * 同时感谢神州数码公司的不思进取让我们能够在与官方、闭源的认证客户端对抗的拉锯战中获得暂时的喘息之机

## 使用指导

  * 编译
  * 安装
  * 参数说明
  * FAQ

## 项目最新动态

  * 2015/7/5 修复了5个Bug，基本目标已实现。项目已经在GitHub上开源。
  * 项目准备进行二次开发，预计于九月初开源
  * 项目基本目标已经在HG255d，基于OpenWrt的路由器上实现
  * 开发阶段已经结束，准备进行调试
  * 报文分析已完成，已转入开发阶段

## 免责声明

  * 涉及神州数码认证的功能来自前辈的贡献及个人抓包的分析
  * 仅供方便认证与共享Wi-Fi，不得用此妨害神州数码认证机制及相关方利益
  * 使用此客户端的一切后果由用户自己承担
