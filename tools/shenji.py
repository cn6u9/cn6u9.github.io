#!/usr/bin/python



import sys,os

shenjilist = ['include||require||require_once||include_once||spl_autoload_register||spl_autoload||file_get_contents','${||exec||system||popen||passthru||proc_open||new ReflectionFunction||new CallbackFilterIterator||pcntl_exec||shell_exec||escapeshellcmd||`','test||simplexml_load_string','eval||preg_replace||assert||call_user_func||call_user_func_array||create_function','_GET||_POST||_COOKIE||_SERVER||_REQUEST||_ENV||php://input||php://phar||getenv','session||cookie','md5||strcmp||sha1||ereg||intval||is_numeric||preg_match||in_array||strpos||strlen||','extract||parse_str||mb_parse_str||import_request_variables||unserialize','copy||rmdir||chmod||delete||fwrite||fopen||readfile||fpassthru||move_uploaded_file||file_put_contents||unlink||upload||opendir||fgetc||fgets||ftruncate||fputs||fputcs','select||insert||update||delete||order by||group by||limit||in(||stripslashes||urldecode','confirm_phpdoc_compiled||mssql_pconnect||mssql_connect||crack_opendict||snmpget||ibase_connect','echo||print||printf||vprintf||document.write||document.innerHTML||document.innerHtmlText','phpinfo||highlight_file||show_source','iconv||mb_convert_encoding','ob_start||array_map||array_map||usort||uasort||uksort||array_filter||array_reduce||array_diff_uassoc||array_diff_ukey||array_udiff||array_udiff_assoc||array_udiff_uassoc||array_intersect_assoc||array_intersect_uassoc||array_uintersect||array_uintersect_assoc||array_uintersect_uassoc||array_walk||preg_filter||mb_ereg_replace||array_walk_recursive||xml_set_character_data_handler||xml_set_default_handler||xml_set_element_handler||xml_set_end_namespace_decl_handler||xml_set_external_entity_ref_handler||xml_set_notation_decl_handler||xml_set_processing_instruction_handler||xml_set_start_namespace_decl_handler||xml_set_unparsed_entity_decl_handler||stream_filter_register||preg_replace_callback||mb_ereg_replace_callback||filter_var||filter_var_array||set_error_handler||register_shutdown_function||runkit_function_rename||register_tick_function']



def print_version():

    print "\n|---------------------------------------------------------------|"

    print "| Usage:    shenji.py  filepath                                   |"

    print "| Example:  shenji.py  /home/root/phpwind                          |"

    print "| or                                                            |"

    print "| Usage:    shenji.py  filepath report(y/n)                       |"

    print "| Example:  shenji.py  home/root/phpwind  y                        |"

    print "|---------------------------------------------------------------|\n"

    

def print_choice():

    global shenjilist

    inum = 0

    print "\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="

    for ipast in shenjilist:

        print inum,":",ipast

        inum = inum + 1

    print "\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="



def shenjiscan(path, itype, report='n'):

    global shenjilist

    reportpath = path

    keylist = shenjilist[itype]

    keylist = keylist.split('||')

    if report.lower() == 'y':

        reportpath = reportpath + '/report'

        if os.path.exists(reportpath) == False:

            os.mkdir(reportpath)

        reportpath = reportpath + '/report.php' 

        print 'Please see you report file:%s'%(reportpath)

    for ikey in keylist:

        if report.lower() == 'y':

            cmd = "grep -in '%s' -r '%s' -3 | grep -v shenji.py | grep -v .css | grep -v .js | grep -v report.php |grep '%s' --color >>'%s'"%(ikey,path,ikey,reportpath)

        else:

            cmd = "grep -in '%s' -r '%s' -3 | grep -v shenji.py | grep -v .css | grep -v .js | grep -v report.php | grep '%s' --color"%(ikey,path,ikey)

        os.system(cmd)

        

def Choose():

    print_choice()

    print "Choose Number:#"

    id = raw_input()

    id = int(id)

    return id



if __name__=='__main__':

    report = 'n'

    if len(sys.argv) < 2:

        print_version()

        sys.exit()

    if len(sys.argv) == 3:

        report = sys.argv[2]

    codepath = sys.argv[1]

    itype = Choose()

    shenjiscan(codepath,itype,report)