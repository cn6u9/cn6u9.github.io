<?php 
function dd($content){
$fp = fopen('./a.txt', 'a+b');
fwrite($fp, print_r($content, true));
fclose($fp);
}
$abc='111';
//dd($abc);
error_log($abc, 3, "./php_3.log");
?>