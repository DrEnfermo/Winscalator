#!/usr/bin/python3

'''
File  userinfo.py
Classses for User information...
Classes UserGroup, UserPriv, UserInfo
It will retrieve all information about systeminfo output.
Author: rtrigo aka Dr.Enfermo (@Dr_Enfermo)
Website: https://github.com/DrEnfermo/Winscalator.git
'''
import csv
import os
import formatting
import wsparser
from pathinfo import PathInfo

class UserGroup:
    def __init__(self, name, type, sid, attributes):
        self.name = name
        self.type = type
        self.sid = sid
        self.attributes = attributes

    def __str__(self):
        return str(self.__dict__)


class UserPriv:
    def __init__(self, name, desc, status):
        self.name = name
        self.desc = desc
        self.status = status

    def __str__(self):
        return str(self.__dict__)



class UserInfo:

    def __init__(self, name, sid, active=True, passwordchangeable = None, passwordexpires=None, passwordrequired=None,is_admin=None,
                 groups=[], privs=[], startuppaths=[], securitypaths=[], pathextfiles=[], proc_integrity_level=''):
        self.name = name
        self.sid = sid
        self.active = active
        self.passwordchangeable = passwordchangeable
        self.passwordexpires = passwordexpires
        self.passwordrequired= passwordrequired
        self.is_admin = is_admin
        self.groups = groups
        self.privs = privs
        self.startuppaths= startuppaths
        self.securitypaths = securitypaths
        self.pathextfiles = pathextfiles
        self.proc_integrity_level = proc_integrity_level

    def __str__(self):
        return str(self.__dict__)

    def asdict(self):
        return {'name' : self.name, 'sid' : self.sid}

    def print_onlyUserInfo(self):
        print(formatting.white_b(self.asdict()))

    def add_groups(self, group_file, onlygroup=False):
        if os.path.exists(group_file) and os.path.isfile(group_file):
            with open(group_file, newline='', encoding='cp850') as f:
                reader = csv.reader(f)
                for row in reader:
                    if onlygroup:
                        group = UserGroup(str(row[0]).strip(),'','','')
                    else:
                        group = UserGroup(str(row[0]).strip(),str(row[1]).strip(),str(row[2]).strip(),str(row[3]).strip())
                    self.groups.append(group)

    def add_group(self, group):
        self.groups.append(group)

    def print_groups(self):
        for group in self.groups:
            print(formatting.white_b(group))

    def add_privileges(self, privs_file):
        if os.path.exists(privs_file) and os.path.isfile(privs_file):
            with open(privs_file, newline='', encoding='cp850') as f:
                reader = csv.reader(f)
                for row in reader:
                    #print(row)
                    priv = UserPriv(row[0],row[1],row[2])
                    self.privs.append(priv)

    def add_priv(self, priv):
        self.privs.append(priv)

    def print_privileges(self):
        for privilege in self.privs:
            print(formatting.white_b(privilege))

    def add_paths(self, outputfile, type):

        if os.path.exists(outputfile) and os.path.isfile(outputfile):
            with open(outputfile, newline='', encoding='cp850') as f:
                lines = f.readlines()
                #print(len(lines))
                for i in range(0, len(lines)):
                    row = lines[i]
                    if len(row) > 1 :
                        # print (str(len(row)))
                        #print("LINE:")
                        #print(row)
                        #print(not str(row).startswith(' '))
                        if not str(row).startswith(' '):
                            if str(row).startswith('[+]') :
                                #print(str(i))
                                if i < len(lines)-1:
                                    next = lines[i + 1]
                                else:
                                    next = ''
                                # print('NEXT LINE: %s' % next)
                                if next.startswith('[+]'):
                                    continue
                                else:
                                    currentpath = None
                                    pathName = ''
                                    owner = ''
                                    del currentpath

                                    if type == "startuppermissions":
                                        'One more field, the user who owns the startup file...'
                                        pathName = str(row).replace('[+] ','').replace('"','').replace('\r\n','').strip().split(',')[0]
                                        owner = str(row).replace('"','').replace('\r\n','').strip().split(',')[1]
                                    else:
                                        pathName = str(row).replace('[+] ','').replace('"','').replace('\r\n','').strip()

                                    currentpath = PathInfo(pathName,[])

                                    if type == "startuppermissions":
                                        'Only startup applications for other users are relevant... (e.g.: SYSTEM, other user to escalate)'
                                        if self.name not in owner:
                                            self.startuppaths.append(currentpath)

                                    if type == "secfilespermissions":
                                        self.securitypaths.append(currentpath)

                                    if type == "extfilespermissions":
                                        self.pathextfiles.append(currentpath)

                            else:
                                    # process permissions from first line (path included)...
                                try:
                                    if isinstance(currentpath, PathInfo):
                                        #print(str(currentpath.pathName).upper())
                                        #print(str(row).upper())
                                        perm = str(row).upper().replace(str(currentpath.pathName.strip()).upper(), '').strip()
                                        #print('- Adding perm %s' % perm)
                                        currentpath.add_permission(perm)
                                except NameError: pass
                        else:
                            try:
                                if isinstance(currentpath, PathInfo):
                                    #process permissions for the rest of permissions
                                    # print('- THE SAME PATH:')
                                    #print(currentpath)
                                    perm = str(row).strip()
                                    if perm not in currentpath.pathPermissions:
                                        #print('- Adding perm %s' % perm)
                                        currentpath.add_permission(perm)
                            except NameError: pass
                # try:
                #         if isinstance(currentpath, PathInfo):
                #                 print(currentpath)
                # except NameError: pass


    def print_paths(self, type):
        if type == "startuppermissions":
            for path in self.startuppaths:
                 print(formatting.white_b(path))

        if type == "extfilespermissions":
            for path in self.pathextfiles:
                print(formatting.white_b(path))

        if type == "extfilespermissions":
            for path in self.pathextfiles:
                print(formatting.white_b(path))

    def print_modifiable_paths(self, type, config_locale_section, filter_winroot=False, sysinfopath = 'C:\\WINDOWS\\'):
        lista = None

        if type == "startuppermissions":
            lista = self.startuppaths
        
        if type == "secfilespermissions":
            lista = self.securitypaths
        
        if type == "extfilespermissions":
            lista = self.pathextfiles

        print()
        for path in lista:
            anywriteperm = False
            if isinstance(path, PathInfo):
                # print(path.pathName)
                if filter_winroot and sysinfopath.upper() in path.pathName.upper():
                    continue
                else:
                    for perm in path.pathPermissions:
                        # print(perm)
                        found = False

                        # Group Everyone has Full access, Modify access or Write access of any kind to this file path...
                        group_everyone = config_locale_section['everyone_group'].upper()
                        # print(group_everyone)
                        if group_everyone == str(perm.split(':')[0]).upper():
                            if 'F' in perm.split(':')[1] or 'W' in perm.split(':')[1] or 'M' in perm.split(':')[1]:
                                print(formatting.red_b('        [!] Path: %s - Group %s has permissions: %s'
                                        % (path.pathName, group_everyone, perm.split(':')[1])))
                                print(formatting.red_b('        [!!!] Everyone could access and modify this files!!!'))
                                found = True

                        # Local Users group has Full access, Modify access or Write access of any kind to this file path...
                        local_users = config_locale_section['local_users_group'].upper()
                        # print(local_users)
                        if local_users == str(perm.split(':')[0]).upper():
                            if 'F' in perm.split(':')[1] or 'W' in perm.split(':')[1] or 'M' in perm.split(':')[1]:
                                print(formatting.red_b('        [!] Path: %s - Group %s has permissions: %s'
                                        % (path.pathName, local_users, perm.split(':')[1])))
                                print(formatting.red_b('        [!!!] Every local user could access and modify this files!!!'))
                                found = True

                        # If user is a local administrator and this group has Full access, Modify access or Write access of any kind to this file path...

                        if isinstance(self.is_admin, bool) and self.is_admin :
                            local_admin_users = config_locale_section['local_admin_group'].upper()
                            # print(local_admin_users)
                            if local_admin_users == str(perm.split(':')[0]).upper():
                                if 'F' in perm.split(':')[1] or 'W' in perm.split(':')[1] or 'M' in perm.split(':')[1]:
                                    print(formatting.red_b('        [!] Path: %s - Group %s has permissions: %s'
                                            % (path.pathName, local_admin_users, perm.split(':')[1])))
                                    found = True
                        else:
                            # The user has Full access, Modify access or Write access of any kind to this file path...
                            if  self.name.upper() == str(perm.split(':')[0]).upper() :
                                if 'F' in perm.split(':')[1] or 'W' in perm.split(':')[1] or 'M' in perm.split(':')[1]:
                                    print(formatting.yellow_b('        [-] Path: %s - User %s has permissions: %s'
                                            %(path.pathName, self.name, perm.split(':')[1])))
                                    print(formatting.red_b('        It could be dangerous if this file is a security/sensitive file...'))
                                    found = True

                        # By the way, if any of the other user groups (it has been stored in the Group objects of userinfo_data object)
                        # has Full access, Modify access or Write access of any kind to this file path...
                        if not found:
                            for group in self.groups:
                                if isinstance(group,UserGroup):
                                    groupname = str(group.name).upper()
                                    if (groupname != group_everyone and groupname != local_users and
                                        groupname != local_admin_users):
                                        # print(group.name.upper())
                                        if  groupname == str(perm.split(':')[0]).upper():
                                            if 'F' in perm.split(':')[1] or 'W' in perm.split(':')[1] or 'M' in perm.split(':')[1]:
                                                print(formatting.green_b('        [-] Path: %s - Group %s has permissions: %s at %s'
                                                        % (path.pathName, group.name, perm.split(':')[1])))
                                                anywriteperm = True
                                                break

                        anywriteperm = anywriteperm or found
                        # if found:
                        #     #found modifiable permission
                        #     break

            if anywriteperm:
                print(formatting.green('-'*79))


    def print_readable_paths(self, type, config_locale_section, filter_winroot=False, sysinfopath = 'C:\\WINDOWS\\'):
        lista = None
        if type == "startuppermissions":
            lista = self.startuppaths
        
        if type == "secfilespermissions":
            lista = self.securitypaths
        
        if type == "extfilespermissions":
            lista = self.pathextfiles

        print()
        for path in lista:
            anyreadperm = False

            if isinstance(path, PathInfo):
            # print(path.pathName)
                res = [f for f in ("SAM","SYSTEM","SECURITY") if(f in path.pathName.upper())]
                if filter_winroot and sysinfopath.upper() in path.pathName.upper():
                    continue
                else:
                    for perm in path.pathPermissions:
                        # print(perm)

                        found = False

                        # Group Everyone has Full access, Modify access or Write access of any kind to this file path...
                        group_everyone = config_locale_section['everyone_group'].upper()
                        # print(group_everyone)
                        if group_everyone == str(perm.split(':')[0]).upper():
                            # if 'F' in perm.split(':')[1] or 'R' in perm.split(':')[1]:
                            if 'R' in perm.split(':')[1]:
                                print(formatting.red_b('        [!!!] Path: %s - Group %s has permissions: %s'
                                        % (path.pathName, group_everyone, perm.split(':')[1])))
                                print(formatting.red_b('              Everyone could read/access/copy this files contents!!!'))

                                if bool(res):
                                    print(formatting.red_b('        [!!!] IF YOU HAVE READ ACCESS TO SAM, SYSTEM AND SECURITY FILES, YOU CAN DUMP THE LOCAL PASSWORDS DATABASE!!'))
                                    print(formatting.red_b('              (EVEN IT COULD BE POTENTIALLY VULNERABLE TO #HiveNightmare aka #SeriousSAM attack!)'))

                                found = True

                        # Local Users group has Full access, Modify access or Write access of any kind to this file path...
                        local_users = config_locale_section['local_users_group'].upper()
                        # print(local_users)
                        if local_users == str(perm.split(':')[0]).upper():
                            # if 'F' in perm.split(':')[1] or 'R' in perm.split(':')[1]:
                            if 'R' in perm.split(':')[1]:
                                print(formatting.red_b('        [!!!] Path: %s - Group %s has permissions: %s'
                                        % (path.pathName, local_users, perm.split(':')[1])))
                                print(formatting.red_b('               Every local user could read/access/copy this files contents!!!'))

                                if bool(res):
                                    print(formatting.red_b('        [!!!] IF YOU HAS READ ACCESS TO SAM, SYSTEM AND SECURITY FILES, YOU CAN DUMP THE LOCAL PASSWORDS DATABASE!!'))
                                    print(formatting.red_b('              (EVEN IT COULD BE POTENTIALLY VULNERABLE TO #HiveNightmare aka #SeriousSAM attack!)'))

                                found = True

                        # If user is a local administrator and this group has Full access, Modify access or Write access of any kind to this file path...
                        if isinstance(self.is_admin, bool) and self.is_admin:
                            local_admin_users = config_locale_section['local_admin_group'].upper()
                            # print(local_admin_users)
                            if local_admin_users == str(perm.split(':')[0]).upper():
                                # if 'F' in perm.split(':')[1] or 'R' in perm.split(':')[1]:
                                if 'R' in perm.split(':')[1]:
                                    print(formatting.red_b('        [!] Path: %s - Group %s has permissions: %s'
                                            % (path.pathName, local_admin_users, perm.split(':')[1])))
                                    found = True
                        else:
                            # The user has Full access, R access of any kind to this file path...
                            if  "%s" % self.name.upper() == str(perm.split(':')[0]).upper():
                                # if 'F' in perm.split(':')[1] or 'R' in perm.split(':')[1]:
                                if 'R' in perm.split(':')[1]:
                                    print(formatting.yellow_b('        [-] Path: %s - User %s has permissions: %s'
                                                               %(path.pathName, self.name, perm.split(':')[1])))
                                    print(formatting.red_b('             It could be dangerous if this file is a security/sensitive file...'))
                                    found = True
                        # By the way, if any of the user groups (it has been stored in the Group objects of userinfo_data object)
                        # has Full access, Modify access or Write access of any kind to this file path...
                        if not found:
                            for group in self.groups:
                                if isinstance(group,UserGroup):
                                    groupname = str(group.name).upper()
                                    if (groupname != group_everyone and groupname != local_users and
                                        groupname != local_admin_users):
                                        # print(group.name)
                                        if  groupname == str(perm.split(':')[0]).upper():
                                            # if 'F' in perm.split(':')[1] or 'R' in perm.split(':')[1]:
                                            if 'R' in perm.split(':')[1]:
                                                print(formatting.green_b('        [-] Path: %s - User\'s Group %s has permissions: %s'
                                                        % (path.pathName, group.name, perm.split(':')[1])))
                                                anyreadperm = True
                                                break

                        anyreadperm = anyreadperm or found
                        # if found:
                        #     #found modifiable permission
                        #     break

            if anyreadperm:
                print(formatting.green('-'*79))



# TODO: Create a method candumpSAMdb or similar...