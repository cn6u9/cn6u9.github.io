---
layout: post
title:  "cve2023-and-web-ctf-tips收集-and-php"
categories: hack
tags:  代码审计
author: cn6u9
---

* content
{:toc}
- 记事本



[web_ctf](https://github.com/cn6u9/cn6u9/blob/main/Web-ctf-cheatsheet.md)  
[pentest_command](https://github.com/cn6u9/cn6u9/blob/main/pentest_linux.md)  
[shenji.py](https://github.com/cn6u9/cn6u9.github.io/blob/main/tools/shenji.py)  
[手工调试php输出](https://github.com/cn6u9/cn6u9.github.io/blob/main/tools/debug.php)  


opengnb  

https://github.com/UCL-CREST/doublefetch c语言静态漏洞挖掘函数  
https://github.com/sha0coder/maripyli 使用python2，是php静态代码分析工具  


windows lpe  
CVE-2023-21752 https://github.com/Wh04m1001/CVE-2023-21752   PoC for arbitrary file delete vulnerability in Windows Backup service
CVE-2023–21746  https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc LPE via StorSvc
CVE-2023-21768 https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768 Windows 11 
CVE-2023-21823 https://github.com/Elizarfish/CVE-2023-21823 windows bitmap组件漏洞 poc应该是假的  
CVE-2023-29336 https://github.com/m-cetin/CVE-2023-29336 Win32k Local Privilege  
CVE-2023-28252 https://github.com/fortra/CVE-2023-28252 clfs.sys  
CVE-2022-44666 https://github.com/j00sean/CVE-2022-44666 Microsoft Windows Contacts  
CVE-2023-24871 https://github.com/ynwarcs/CVE-2023-24871 Windows Bluetooth 服务远程代码执行漏洞  
CVE-2023-23388 https://github.com/ynwarcs/CVE-2023-23388 Windows Bluetooth 驱动程序特权提升漏洞  
CVE-2023-36899 https://github.com/d0rb/CVE-2023-36899 ASP.NET Elevation of Cookieless IIS Auth Bypass & App Pool Privesc  
CVE-2023-36874 https://github.com/d0rb/CVE-2023-36874 Windows Error Reporting Service lpe  
CVE-2023-36900 https://github.com/RomanRybachek/CVE-2023-36900 Windows Common Log File System Driver Elevation of Privilege Vulnerability  
CVE-2023-28229 https://github.com/Y3A/CVE-2023-28229 Windows CNG Key Isolation Service Elevation of Privilege Vulnerability  
CVE-2023-29360 https://github.com/Nero22k/cve-2023-29360 Microsoft Streaming Service Elevation of Privilege Vulnerability windows流媒体提全  
CVE-2023-36802 https://github.com/chompie1337/Windows_MSKSSRV_LPE_CVE-2023-36802 Windows 11 22H2  
CVE-2023-36723 https://github.com/Wh04m1001/CVE-2023-36723 Windows Container Manager Service Elevation of Privilege Vulnerability  
CVE-2023-36025 https://github.com/DamnIt74/CVE-2023-36025 Windows Defendor SmartScreen Bypass POC Exploit Code  
CVE-2023-36036 https://bbs.kanxue.com/thread-279771.htm 无poc，过几天更新 Windows Cloud Files Mini Filter Driver 权限提升  
CVE-2023-41772 https://github.com/R41N3RZUF477/CVE-2023-41772 Win32k Elevation of Privilege Vulnerability  
CVE-2023-36424 https://ssd-disclosure.com/ssd-advisory-windows-kernel-pool-clfs-sys-corruption-privilege-escalation/ Windows systems running 64-bit clfs.sys with version 10.0.22621.1555  
CVE-2023-28229 https://github.com/Y3A/CVE-2023-28229 Windows CNG KeyIso RPC EoP/SBX  
CVE-2023-36003 https://github.com/m417z/CVE-2023-36003-POC Microsoft XAML Diagnostics Elevation of Privilege Vulnerability  
CVE-2024-20698 https://github.com/RomanRybachek/CVE-2024-20698 Windows Kernel Elevation of Privilege Vulnerability  
CVE-2024-20666 https://github.com/nnotwen/Script-For-CVE-2024-20666 BitLocker vulnerabilit win10 win11 windows2022  
CVE-2024-21338 https://github.com/gogobuster/CVE-2024-21338-POC lpe Windows 10 1703 (RS2/15063) Windows 11 23H2  
CVE-2024-21306 https://github.com/d4rks1d33/C-PoC-for-CVE-2024-21306 Microsoft Bluetooth Driver Spoofing Vulnerability  
CVE-2024-26218 https://github.com/exploits-forsale/CVE-2024-26218 Windows 内核特权提升漏洞  
CVE-2024-21345 https://github.com/exploits-forsale/CVE-2024-21345 Windows 内核特权提升漏洞  
CVE-2024-29988 https://github.com/Sploitus/CVE-2024-29988-exploit Exploit for Microsoft SmartScreen malicious execution  
CVE-2024-26229 https://github.com/varwara/CVE-2024-26229 Windows CSC Service Elevation of Privilege Vulnerability  
CVE-2024-30088 https://github.com/tykawaii98/CVE-2024-30088 Windows Kernel Elevation of Privilege Vulnerability  
CVE-2024-37726 https://github.com/carsonchan12345/CVE-2024-37726-MSI-Center-Local-Privilege-Escalation MSI Center LPE  
CVE-2024-38041 https://github.com/varwara/CVE-2024-38041 Windows appid.sys内核信息泄露漏洞  
CVE-2024-38100 https://github.com/Florian-Hoth/CVE-2024-38100-RCE-POC Windows File Explorer Elevation of Privilege Vulnerability  
CVE-2024-26230 https://github.com/kiwids0220/CVE-2024-26230 Windows Telephony启用电话服务器特权提升漏洞  
CVE-2024-6768 https://github.com/fortra/CVE-2024-6768 CLFS.sys服务拒绝（DoS）漏洞  
CVE-2024-26160 https://github.com/0x00Alchemist/CVE-2024-26160 cldflt.sys 信息泄漏  
CVE-2024-38080 https://github.com/pwndorei/CVE-2024-38080 Windows Hyper-V 特权提升漏洞  
CVE-2024-30051 https://github.com/fortra/CVE-2024-30051 Windows DWM Core Library lpe  
CVE-2024-45383 https://github.com/SpiralBL0CK/CVE-2024-45383 Microsoft High Definition Audio Bus Driver 安全漏洞  
CVE-2024-38144 https://github.com/Dor00tkit/CVE-2024-38144 windows Kernel Streaming WOW Thunk 服务驱动程序特权提升漏洞  
CVE-2024-29050 https://github.com/Akrachli/CVE-2024-29050 Windows' cryptographic services  
CVE-2024-35250 https://github.com/varwara/CVE-2024-35250 Windows 内核模式驱动程序特权提升漏洞ks.sys  
CVE-2024-30090 https://github.com/Dor00tkit/CVE-2024-30090 Microsoft 流式处理服务特权提升漏洞  
CVE-2024-38193 https://github.com/Nephster/CVE-2024-38193 WinSock的Windows辅助功能驱动程序特权提升漏洞  


windows rce  

CVE-2022-34718 https://github.com/numencyber/Vulnerability_PoC/blob/main/CVE-2022-34718/poc.cpp  TCP/IP RCE Vulnerability  
CVE-2023-28231 https://github.com/numencyber/Vulnerability_PoC/blob/main/CVE-2023-28231/CVE-2023-28231-DHCP-VUL-PoC.cpp  MICROSOFT WINDOWS SERVER 2008-2019 DHCP SERVER  
CVE-2023-28231 https://github.com/glavstroy/CVE-2023-28231  MICROSOFT WINDOWS SERVER 2008-2019 DHCP SERVER   
CVE-2023-38148 https://github.com/Chestnuts4/POC/blob/master/CVE-https://github.com/synacktiv/php_filter_chains_oracle_exploit 有意思的漏洞  2023-38148-windows-ics-rce/CVE-2023-38148.c Internet Connection Sharing (ICS) RCE  
CVE-2024-20696 https://github.com/clearbluejar/CVE-2024-20696 Windows Libarchive 远程代码执行漏洞  
CVE-2024-30078 https://github.com/kvx07/CVE_2024_30078_A_POC Windows Wi-Fi Driver Remote Code Execution Vulnerability  
CVE-2024-38077 https://github.com/CloudCrowSec001/CVE-2024-38077-POC/blob/main/CVE-2024-38077-poc.py Windows 远程桌面授权服务远程代码执行漏洞  
CVE-2024-38063　https://github.com/diegoalbuquerque/CVE-2024-38063　Windows TCP/IP 远程执行代码漏洞  

php  
cve-2024-1874 https://github.com/php/php-src/security/advisories/GHSA-pc52-254m-w9w7 PHP直到8.1.27/8.2.17/8.3.4WINDOWS PROC_OPEN 权限升级  
CVE-2020-7071 https://github.com/php/php-src/security/advisories/GHSA-w8qr-v226-r27w Filter bypass in filter_var 7.327-8.37  
CVE-2024-5458 https://github.com/justmexD8/CVE-2024-5458-POC filter_var (FILTER_VALIDATE_URL) 中的过滤器绕过  

office and word and pdf and rar and wps  

CVE_2023_21716 https://github.com/Xnuvers007/CVE-2023-21716    RTF Crash POC  
cve-2023-23397 https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY  microsoft-outlook-elevation-of-privilege-vulnerability  
CVE-2023-27363 https://github.com/webraybtl/CVE-2023-27363 福昕Foxit PDF远程代码执行漏洞  
CVE-2023-36884 Office and Windows HTML Remote Code Execution Vulnerability  
CVE-2022-30190 https://github.com/komomon/CVE-2022-30190-follina-Office-MSDT-Fixed Microsoft Office MSDT  
CVE-2023-40477 https://github.com/cn6u9/cn6u9.github.io/blob/main/tools/CVE-2023-40477.sh winrar rce  
CVE-2023-38831 https://github.com/Garck3h/cve-2023-38831 winrar rce  
wps rce  https://github.com/ba0gu0/wps-rce WPS Office 2023 个人版 < 11.1.0.15120---WPS Office 2019 企业版 < 11.8.2.12085  
CVE-2024-7262 https://www.4hou.com/posts/5MWx WPS Office从路径穿越到远程代码执行漏洞  
CVE-2022-21974 https://github.com/0vercl0k/CVE-2022-21974 winword  
CVE-2023-28288 https://www.exploit-db.com/exploits/51543 Microsoft SharePoint Enterprise Server 2016 - Spoofing  
CVE-2023-36563 无poc Microsoft WordPad Information Disclosure Vulnerability  
CVE-2023-21608 https://github.com/hacksysteam/CVE-2023-21608 Adobe Acrobat Reader CAgg UaF RCE Exploit  
CVE-2024-4367 https://github.com/Zombie-Kaiser/cve-2024-4367-PoC-fixed PDF.js是由Mozilla维护的基于JavaScript的PDF查看器  
CVE-2024-38200 https://github.com/passtheticket/CVE-2024-38200 Microsoft Office 欺骗漏洞  


linux lpe  

CVE-2023-22809  https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc   sudo 1.8.0 to 1.9.12p1

CVE-2023-0179   https://github.com/TurtleARM/CVE-2023-0179-PoC    Linux versions from 5.5 to 6.2-rc3

CVE-2023-0045   https://github.com/es0j/CVE-2023-0045        ubuntu 22.04.1-Linux 5.15.0-56-generic

CVE-2023-2002   https://github.com/lrh2000/CVE-2023-2002/blob/master/exp/bt_power.c 蓝牙提权  
CVE-2023-0386   https://github.com/xkaneiki/CVE-2023-0386  ubuntu提权   
CVE-2023-20052  https://github.com/nokn0wthing/CVE-2023-25002   clamav 杀毒xxe注入   
CVE-2023-20032  https://github.com/cn6u9/cn6u9.github.io/blob/main/tools/hfsplus.zip   clamav HFS+ file parser rce     
CVE-2023-2008   https://github.com/bluefrostsecurity/CVE-2023-2008  Ubuntu 22.04 Linux kernel fixed in 5.19-rc4

CVE-2023-1829 https://github.com/lanleft/CVE2023-1829 Ubuntu22.04 source code 5.15.0-25.25  
CVE-2023-32233 https://github.com/Liuk3r/CVE-2023-32233 Ubuntu 23.04 linux-image-6.2.0-20-generic  
CVE-2023-3338 https://github.com/TurtleARM/CVE-2023-3338 linux kernel 5.15  
CVE-2023-35001 https://github.com/synacktiv/CVE-2023-35001 Ubuntu desktop 5.19.0-35  
CVE-2023-35829 https://github.com/ChriSanders22/CVE-2023-35829-poc Linux kernel 6.3.2.use-after-free was found in rkvdec_remove  
CVE-2023-2640 https://github.com/luanoliveira350/GameOverlayFS OverlayFS Ubuntu 20.04 with kernel 5.4.0  
CVE-2023-32629 https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629 Ubuntu 18.04 and 22.04 LTS  kernels 5.19.0 and 6.2.0  
CVE-2023-4911 https://github.com/RickdeJager/CVE-2023-4911 Ubuntu 22.10  glibc 2.34 ld.so  
cve-2023-4813 https://github.com/tnishiox/cve-2023-4813 gaih_inet() 中潜在的释放后使用  
CVE-2023-3269 
CVE-2023-1521 https://github.com/rubbxalc/CVE-2023-1521 Linux the sccache client lpe  
cve-2023-2598 https://github.com/ysanatomic/io_uring_LPE-CVE-2023-2598/blob/main/exploit.c Linux Kernel io_uring 拒绝服务漏洞  
CVE-2023-50254 https://github.com/febinrev/deepin-linux_reader_RCE-exploit Deepin Linux的默认文档阅读器deepin-reader在版本6.0.7  
CVE-2023-6546 https://github.com/torvalds/linux/commit/3c4f8333b582487a2d1e02171f1465531cde53e3 Linux Kernel GSM Multiplexing Race Condition LPE  
cve-2023-5345 https://avd.aliyun.com/detail?id=AVD-2023-5345 无poc Linux 内核的 fs/smb/client 组件中的释放后使用  
CVE-2023-6246 无poc GNU C库的__vsyslog_internal()函数中的存在堆基缓冲区溢出漏洞，lpe 影响挺大  
CVE-2023-52447 https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2023-52447_cos lpe  
https://github.com/vusec/ghostrace Linux kernel v5.15.83 for Speculative Concurrent Use-After-Free (SCUAF) gadgets  
CVE-2024-1086 https://github.com/Notselwyn/CVE-2024-1086 Linux kernel v5.14 and v6.6, including Debian, Ubuntu, and KernelCTF  
CVE-2024-0582 https://github.com/ysanatomic/io_uring_LPE-CVE-2024-0582 linux内核通过缓冲区环 mmap 的页面释放后  
CVE-2024-28085 https://github.com/skyler-ferrante/CVE-2024-28085 linux标准软件包 util-linux <2.40 setid 提权漏洞  
CVE-2024-2961 https://github.com/mattaperkins/FIX-CVE-2024-2961 glibc 安全漏洞The iconv() function in the GNU C Library versions 2.39  
CVE-2024-2961 https://github.com/m4p1e/php-exploit/blob/master/CVE-2024-2961/exp.py roundcube邮件服务器利用方式  
CVE-2024-37383 https://github.com/bartfroklage/CVE-2024-37383-POC Roundcube Webmail before 1.5.7 and 1.6.x before 1.6.7 allows XSS via SVG  
CVE-2024-0193 https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2024-0193_cos/ netfilter uaf lpe  
CVE-2024-44946　https://github.com/Abdurahmon3236/CVE-2024-44946　linux kcm_uaf_poc lpe  
CVE-2024-42642 https://github.com/VL4DR/CVE-2024-42642/tree/main ssd磁盘提权漏洞　　
CVE-2024-47176 https://github.com/lkarlslund/jugular CUPS 远程命令执行漏洞  



Exchange  and  outlook  and hyper-v  and word and ppt and SharePoint  
CVE-2022-41082 https://github.com/balki97/OWASSRF-CVE-2022-41082-POC NotProxyShell OWASSRF Vul Effecting Microsoft Exchange 

CVE-2023-21707 https://github.com/N1k0la-T/CVE-2023-21707 Microsoft Exchange Server Remote Code Execution Vulnerability  
CVE-2023-23397 https://github.com/CKevens/CVE-2023-23397-POC/blob/main/CVE-2023-23397.py outlook 2019 auto get NetNTLM  
CVE-2023-29357 https://github.com/Chocapikk/CVE-2023-29357 Microsoft SharePoint Server Elevation of Privilege Vulnerability  
CVE-2023-36745 https://github.com/N1k0la-T/CVE-2023-36745  Microsoft Exchange Server Remote Code Execution Vulnerability 需要在内网，需要有帐号  
CVE-2023-32031 https://github.com/Avento/CVE-2023-32031 CVE-2023-32031 MS Exchange PowerShell backend RCE  
CVE-2023-36427 https://github.com/tandasat/CVE-2023-36427 Windows Hyper-V 特权提升漏洞  
CVE-2023-24955 https://github.com/former-farmer/CVE-2023-24955-PoC Microsoft SharePoint 2019  
CVE-2024-21413 https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability Microsoft Outlook RCE PoC  
CVE-2024-21378 https://github.com/JohnHormond/CVE-2024-21378 Microsoft Outlook 远程代码执行漏洞  
CVE-2024-30043 https://github.com/W01fh4cker/CVE-2024-30043-XXE Microsoft Sharepoint Server 2019(16.0.10409.20027)  
CVE-2024-38127 https://github.com/pwndorei/CVE-2024-38127 Windows Hyper-V 特权提升漏洞  


域控  
https://github.com/Amulab/advul  
CVE-2020-1472  
CVE-2021-42287  
CVE-2022-26923  
CVE-2022-33679  

web  

Joomla 未授权访问漏洞 CVE-2023-23752  
CVE-2023-34192 Zimbra XSS To RCE  
CVE-2023-28467 mybb1.8.33 email xss  
CVE-2023-32315 https://github.com/Pari-Malam/CVE-2023-32315 openfire  
CVE-2023-29489 https://github.com/ViperM4sk/cpanel-xss-177 cPanel 11.102.0.x-11.109.9999.116 xss  
CVE-2023-25135 https://github.com/getdrive/PoC/tree/main/2023/vbulletin vbulletin.version:<=5.6.9 rce  

Spring Framework 6.0.7 and 5.3.26 fix cve-2023-20860 and cve-2023-20861  
CVE-2023-34039 https://github.com/Cyb3rEnthusiast/CVE-2023-34039 VMware newest exploit  
CVE-2023-41362 https://github.com/SorceryIE/CVE-2023-41362_MyBB_ACP_RCE MyBB_ACP_RCE  
CVE-2023-22515 https://github.com/Chocapikk/CVE-2023-22515 Confluence Data Center  
CVE-2023-39539 https://github.com/AdamWen230/CVE-2023-39539-PoC cacti 1.2.22 rce  
CVE-2020-35701 https://asaf.me/2020/12/15/cacti-1-2-0-to-1-2-16-sql-injection/ cacti 1.2.14 sql to rce  
cve-2023-47444 https://0xbro.red/disclosures/disclosed-vulnerabilities/opencart-cve-2023-47444/  OpenCart版本4.0.0.0至4.0.2.3存在个漏洞  
cve-2023-34034 https://github.com/hotblac/cve-2023-34034 Spring Security 路径匹配权限绕过漏洞  
CVE-2023-25690 https://github.com/thanhlam-attt/CVE-2023-25690 Apache HTTP Server 存在请求走私漏洞  
CVE-2023-50164 https://github.com/jakabakos/CVE-2023-50164-Apache-Struts-RCE Apache Struts path traversal to RCE vulnerability  
CVE-2023-41892 https://github.com/Faelian/CraftCMS_CVE-2023-41892 CraftCMS Unauthenticated RCE  
CVE-2023-22527 https://github.com/Avento/CVE-2023-22527_Confluence_RCE Confluence Data Center and Confluence Server rce  
CVE-2023-39362 https://github.com/m3ssap0/cacti-rce-snmp-options-vulnerable-application Cacti v1.2.24 auth cmd inject 需要登录  
无cve https://github.com/Cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88 cacti漏洞点位置  
CVE-2024-29895 https://github.com/Stuub/CVE-2024-29895-CactiRCE-PoC  
CVE-2024-25641 https://github.com/5ma1l/CVE-2024-25641 RCE for Cacti 1.2.26  
CVE-2024-43363 https://github.com/p33d/CVE-2024-43363 通过 Cacti 中的日志中毒执行远程代码  
CVE-2023-41892 https://github.com/diegaccio/Craft-CMS-Exploit Craft CMS Versions between 4.0.0-RC1 - 4.4.14  
CVE-2024-23897 https://github.com/godylockz/CVE-2024-23897 file-read access on a Jenkins server <= version 2.441  
CVE-2024-34144 https://github.com/MXWXZ/CVE-2024-34144 Jenkins 脚本安全插件存在涉及精心设计的构造函数体的沙箱绕过漏洞  
CVE-2024-43044 https://github.com/HwMex0/CVE-2024-43044 Jenkins agent connections 文件读取漏洞  
CVE-2024-22234 https://github.com/shellfeel/CVE-2024-22243-CVE-2024-22234 Spring Security 6.1.7之前的6.1.x版本和6.2.2之前的6.2.x  
CVE-2024-38816 https://github.com/weliveby/cve-2024-38816-demo/tree/master Spring Framework 特定条件下目录遍历漏洞  
CVE-2024-21683 https://github.com/absholi7ly/-CVE-2024-21683-RCE-in-Confluence-Data-Center-and-Server Confluence需要帐号密码  
CVE-2024-34102 https://github.com/bigb0x/CVE-2024-34102 Adobe Commerce/Magento estimate-shipping-methods XXE漏洞  
CVE-2024-44902 https://github.com/fru1ts/CVE-2024-44902 Thinkphp v6.1.3 to v8.0.4反序列化  
CVE-2024-45519 https://github.com/Chocapikk/CVE-2024-45519 Zimbra RCE  


Critical and IOT and Router and nas and Cisco and teamview  
CVE-2023-3519 https://github.com/getdrive/PoC/tree/main/2023/Citrix%20ADC%20RCE%20CVE-2023-3519 Citrix VPX 13.1-48.47  
https://ssd-disclosure.com/ssd-advisory-zyxel-vpn-series-pre-auth-remote-command-execution/  Zyxel VPN firewall VPN50, VPN100, VPN300, VPN500, VPN1000  
CVE-2024-27497 https://www.seebug.org/vuldb/ssvid-99816 linksys e2000 bug  
CVE-2024-3273 https://github.com/Chocapikk/CVE-2024-3273 d-link nas rce 8w台  
CVE-2024-10914 https://github.com/verylazytech/CVE-2024-10914 d-link nas rce  
CVE-2024-29269 https://github.com/YongYe-Security/CVE-2024-29269 Telesquare TLR-2005KSH_RCE for kr  
CVE-2024-20359 https://github.com/Garvard-Agency/CVE-2024-20359-CiscoASA-FTD-exploit CVE-2024-20359-CiscoASA-FTD-exploit  
CVE-2024-20356 https://github.com/nettitude/CVE-2024-20356 Cisco Integrated Management Controller 操作系统命令注入漏洞  
CVE-2024-26304 https://github.com/Roud-Roud-Agency/CVE-2024-26304-RCE-exploits Critical RCE Vulnerabilities in HPE  
CVE-2024-29973 https://github.com/bigb0x/CVE-2024-29973 Zyxel NAS542 操作系统命令注入漏洞  
CVE-2024-29975 https://mp.weixin.qq.com/s/hs8PJOIw7DFyzv5fCUKwlw 包含了CVE-2024-29972-NsaRescueAngel 后门账户CVE-2024-29976 – 权限提升和信息泄露漏洞CVE-2024-29973 – Python 代码注入漏洞  
CVE-2024-7357 https://github.com/BeaCox/IoT_vuln/tree/main/D-Link/DIR-600/soapcgi_main_injection D-Link DIR-600 soap.cgi soapcgi_main os 命令注入  
CVE-2024-7479 & CVE-2024-7481 https://github.com/PeterGabaldon/CVE-2024-7479_CVE-2024-7481 TeamViewer User to lpe  


mail and exim  
CVE-2024-39929 https://github.com/michael-david-fry/CVE-2024-39929 Exim through 4.97.1 misparses a multiline RFC 2231 header filename  


Browser  

chrome cvc-2023-2033 无poc  
CVE-2023-4427 https://github.com/tianstcht/CVE-2023-4427 chrome version: 117.0.5938.62 in linux from v8ctf  
chrome CVE-2023-3079 https://github.com/mistymntncop/CVE-2023-3079    
chrome CVE-2023-4863 https://github.com/mistymntncop/CVE-2023-4863 WebP in Google Chrome prior to 116.0.5845.187  
chrome CVE-2023-4762 https://github.com/sherlocksecurity/CVE-2023-4762-Code-Review Google Chrome prior to 116.0.5845.179  
ios Safari 17 CVE-2023-41993 https://github.com/po6ix/POC-for-CVE-2023-41993 iOS 16.7 and iPadOS 16.7, macOS Sonoma 14  
cve-2024-0517 https://blog.exodusintel.com/2024/01/19/google-chrome-v8-cve-2024-0517-out-of-bounds-write-code-execution/  
CVE-2024-0519 https://github.com/JohnHormond/CVE-2024-0519-Chrome-exploit Google Chrome V8 < 120.0.6099.224  
CVE_2023_3420 https://github.com/paulsery/CVE_2023_3420 CVE_2023_3420  Google Chrome V8 114.0.5735.198之前版本存在堆损坏安全漏洞  
cve-2023-4357 https://github.com/xcanwin/CVE-2023-4357-Chrome-LFI Chrome任意文件读取漏洞POC  
CVE-2024-21388 https://github.com/d0rb/CVE-2024-21388 Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability  
CVE-2024-3159 https://bbs.kanxue.com/thread-281484.htm Chromium: CVE-2024-3159 Out of bounds memory access in V8  
CVE-2024-4761 https://github.com/michredteam/CVE-2024-4761 124.0.6367.207/.208 for Mac and Windows and 124.0.6367.207之前版本  
CVE-2024-30056 https://github.com/absholi7ly/Microsoft-Edge-Information-Disclosure Microsoft Edge信息泄漏  
CVE-2024-29943CVE-2024-29943 https://github.com/bjrjk/CVE-2024-29943 firefox rce  
CVE-2024-9680 https://github.com/tdonaworth/Firefox-CVE-2024-9680 firefox 引用重释放漏洞  
CVE_2024_3833 https://github.com/github/securitylab/tree/main/SecurityExploits/Chrome/v8/CVE_2024_3833 Chrome version 123.0.6312.58 on Ubuntu 22.04  
CVE-2024-2887 https://github.com/rycbar77/CVE-2024-2887 chrome claim V8CTF M123  
CVE-2024-1939 https://github.com/rycbar77/CVE-2024-1939  claim V8CTF M122  
CVE-2024-6778 https://github.com/ading2210/CVE-2024-6778-POC CVE-2024-5836 / CVE-2024-6778代码执行  




Oracle  and weblogic and geoserver and Ivanti  
CVE-2023-22074 https://github.com/emad-almousa/CVE-2023-22074 Oracle Database Server 19.3-19.20 and 21.3-21.11  
CVE-2022-21445 https://github.com/StevenMeow/CVE-2022-21445 Oracle ADF Faces 反序列化RCE  
Weblogic CVE-2023-21839 https://github.com/GlassyAmadeus/CVE-2024-20931  
Weblogic CVE-2023-21931  无poc  
weblogic https://github.com/MMarch7/weblogic_CVE-2023-21931_POC-EXP  
CVE-2023-35042 https://isc.sans.edu/diary/Geoserver+Attack+Details+More+Cryptominers+against+Unconfigured+WebApps/29936/ GeoServer 2 远程代码执行漏洞  
CVE-2023-25157 https://github.com/7imbitz/CVE-2023-25157-checker geoserver sql inject  
cve-2024-36401 https://github.com/bigb0x/CVE-2024-36401/blob/main/cve-2024-36401.py geoserver rce  
CVE-2024-20931 https://github.com/labesterOct/CVE-2024-20931 Weblogic T3\IIOP protocol A new attack  
CVE-2024-21893 https://github.com/h4x0r-dz/CVE-2024-21893.py Ivanti Policy Secure (9.x, 22.x)  
CVE-2024-29824 https://github.com/horizon3ai/CVE-2024-29824 Ivanti EPM SQL Injection RCE  
CVE-2024-29847 https://github.com/horizon3ai/CVE-2024-29847 Ivanti 存在反序列化漏洞  
CVE_2024_22024 https://github.com/tequilasunsh1ne/ivanti_CVE_2024_22024 Ivanti Pulse Connect Secure VPN XXE 漏洞还有CVE_2024_8190　　

CVE-2024-21006 https://github.com/momika233/CVE-2024-21006 Oracle WebLogic Server 12.2.1.4.0 and 14.1.1.0.0  


vmware esxi and vcenter and Fortinet and VirtualBox and docker  
cve-2022-31705 https://github.com/s0duku/cve-2022-31705 Test on windows vmware workstation 16.2.0, with guest os ubuntu server 22  
CVE-2021-21974 https://github.com/Shadow0ps/CVE-2021-21974 VMWare ESXi RCE Exploit  
cve-2022-31680 https://www.idappcom.co.uk/post/vmware-vcenter-server-code-execution-cve-2022-31680 有帐号之后才能提权  
CVE-2023-36553 https://github.com/kenit7s/CVE-2023-36553-RCE Fortinet FortiSIEM版本 RCE  
CVE-2024-21626 https://github.com/Wall1e/CVE-2024-21626-POC ocker server:20.10.17 && runc version 1.1.2 逃逸漏洞  
CVE-2024-21762 https://github.com/Gh71m/CVE-2024-21762-POC?tab=readme-ov-file FortiProxy 1.07-7.40执行未授权的代码或命令  
CVE-2024-21111 https://github.com/mansk1es/CVE-2024-21111 Oracle VirtualBox Prior to 7.0.16 lpe  
CVE-2024-21754 https://github.com/CyberSecuritist/CVE-2024-21754-Forti-RCE FortiOS and FortiProxy Password Hashing Vulnerability to RCE无poc  
CVE-2024-23113 https://github.com/puckiestyle/CVE-2024-23113 Fortinet FortiOS 格式化字符串错误漏洞  
CVE-2024-37081 https://github.com/mbadanoiu/CVE-2024-37081 VMware vCenter Server LPE  
CVE-2024-22275 https://github.com/mbadanoiu/CVE-2024-22275 VMware vCenter Server File Read  
CVE-2024-22274 https://github.com/l0n3m4n/CVE-2024-22274-RCE VMware vCenter Server Authenticated RCE  
CVE-2024-37085 https://github.com/Florian-Hoth/CVE-2024-37085-RCE-POC VMware ESXi RCE Vulnerability  
CVE-2024-6222 https://github.com/Florian-Hoth/CVE-2024-6222 Docker Extension/Dashboard RCE Vulnerability  





Macos and ios 
CVE-2023-41991 macos   
CVE-2023-41993 iphone_os  
CVE-2024-25733 https://github.com/hackintoanetwork/ARC-Browser-Address-Bar-Spoofing-PoC ARC Browser Address Bar Spoofing  
CVE-2024-27804 https://github.com/R00tkitSMM/CVE-2024-27804 ios 17.5本地提权  
CVE-2024-27815 https://github.com/jprx/CVE-2024-27815 tvOS 17.5, visionOS 1.2, iOS 17.5 and iPadOS 17.5, watchOS 10.5, macOS Sonoma 14.5  


php  
https://github.com/synacktiv/php_filter_chains_oracle_exploit 有意思的漏洞  
cve-2023-3824 https://github.com/php/php-src/security/advisories/GHSA-jqcx-ccgc-xwhv phar_dir_read()overflow  
CVE-2023-3824 https://github.com/m4p1e/php-exploit/tree/master/CVE-2023-3824  

qnap and nas  
CVE-2023-47218 https://github.com/passwa11/CVE-2023-47218 qnap rce  
CVE-2023-39296 https://ssd-disclosure.com/ssd-advisory-qnap-qts5-usr-lib-libqcloud-so-json-parsing-leads-to-rce/  qnap rce  
CVE-2021-28797 https://ssd-disclosure.com/ssd-advisory-qnap-pre-auth-cgi_find_parameter-rce/  qnap rce  
CVE-2024-27130 https://github.com/watchtowrlabs/CVE-2024-27130/ qnap stack overflow vulnerability to obtain RCE  
qnap rce  
CVE-2023-50361 Unsafe use of sprintf in getQpkgDir invoked from userConfig.cgi leads to stack buffer overflow and thus RCE  
CVE-2023-50362Unsafe use of SQLite functions accessible via parameter addPersonalSmtp to userConfig.cgi leads to stack buffer overflow and thus RCE  
CVE-2023-50364 Heap overflow via long directory name when file listing is viewed by get_dirs function of privWizard.cgi leads to RCE  
CVE-2024-27127 A double-free in utilRequest.cgi via the delete_share function  
CVE-2024-27128 Stack overflow in check_email function, reachable via the share_file and send_share_mail actions of utilRequest.cgi (possibly others) leads to RCE  
CVE-2024-27129 Unsafe use of strcpy in get_tree function of utilRequest.cgi leads to static buffer overflow and thus RCE  
CVE-2024-27130 Unsafe use of strcpy in No_Support_ACL accessible by get_file_size function of share.cgi leads to stack buffer overflow and thus RCE  
CVE-2024-32766 https://github.com/3W1nd4r/CVE-2024-32766-RCE  无poc qnap RCE  


apache  
CVE-2024-32113 https://github.com/Mr-xn/CVE-2024-32113 Apache OFBIZ Path traversal leading to RCE EXP  
CVE-2024-27348 https://github.com/Zeyad-Azima/CVE-2024-27348 Apache HugeGraph Server RCE  
CVE-2024-40725 https://github.com/TAM-K592/CVE-2024-40725-CVE-2024-40898 Apache HTTP Server 源代码泄露漏洞  


other  

CVE-2022-44268 https://github.com/agathanon/cve-2022-44268 ImageMagick
cve-2022-31705 https://github.com/s0duku/cve-2022-31705 windows vmware workstation 16.2.0

CVE-2022-26923 域提权  
CVE-2023-27997 FortiOS SSL-VPN buffer overflow vulnerability  

CVE-2023-21554-RCE https://github.com/zoemurmure/CVE-2023-21554-PoC   Windows MessageQueuing PoC  
CVE-2023-2868  https://github.com/cfielding-r7/poc-cve-2023-2868 梭子鱼本地提权漏洞poc在本地  
CVE-2023-3519 Citrix RCE  
CVE-2023-4966 https://github.com/Chocapikk/CVE-2023-4966 Citrix Memory Leak Exploit  
CVE-2023-43177 https://github.com/the-emmons/CVE-2023-43177 CrushFTP <= 10.5.1 RCE  
CVE-2023-20598 https://github.com/H4rk3nz0/CVE-2023-20598-PDFWKRNL AMD Radeon 安全漏洞  

CVE-2023-20871  https://github.com/ChriSanders22/CVE-2023-20871-poc VMware Fusion Raw Disk local privilege escalation vulnerability  
CVE-2023-34312  https://github.com/vi3t1/qq-tim-elevation Tencent QQ/TIM Local Privilege Elevation  
CVE-2023-40031 https://github.com/webraybtl/CVE-2023-40031 notepad++堆缓冲区溢出漏洞  
CVE-2023-26818 https://github.com/Zeyad-Azima/CVE-2023-26818 Telegram  
CVE-2023-38545 https://github.com/imfht/CVE-2023-38545 curl 堆溢出 影响面积挺大  
CVE-2023-34051 https://github.com/horizon3ai/CVE-2023-34051 VMware vRealize Log Insight  
CVE-2023-46747 https://github.com/AliBrTab/CVE-2023-46747-POC F5 BIG-IP unauthenticated remote code execution  
CVE-2023-51385 https://github.com/FeatherStark/CVE-2023-51385 OpenSSH <9.6 命令注入漏洞  
CVE-2024-6387 https://github.com/xonoxitron/regreSSHion openssh 8.5p1 <= OpenSSH < 9.8p1 条件竞争漏洞  
CVE-2023-51764 https://github.com/duy-31/CVE-2023-51764 Postfix SMTP Smuggling - Expect Script POC  
cve-2024-3116 https://ayoubmokhtar.com/post/remote_code_execution_pgadmin_8.4-cve-2024-3116/ pgAdmin - PostgreSQL Tools (<=8.4)  
CVE-2024-24576 https://github.com/frostb1ten/CVE-2024-24576-PoC Rust flaw enables Windows command injection attacks  
CVE-2024-32459 https://github.com/absholi7ly/FreeRDP-Out-of-Bounds-Read-CVE-2024-32459- FreeRDP 3.5.0 或 2.11.6 之前版本的客户端和服务器存在越界读漏洞  
CVE-2024-40431　https://github.com/SpiralBL0CK/CVE-2024-40431-CVE-2022-25479-EOP-CHAIN　realtek声卡显卡驱动，RtsPer.sys信息泄漏　　



# 小结
