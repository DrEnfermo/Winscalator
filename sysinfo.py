#!/usr/bin/python3
import csv
import os
import formatting
from userinfo import UserInfo
from servinfo import ServiceInfo
from procinfo import ProcessInfo
from schtaskinfo import SchTaskInfo
from passwordinfo import PasswordInfo

'''
File sysinfo.py
Class: SystemInfo
It will retrieve all information about systeminfo output.
Author: R. Trigo aka Dr.Enfermo (@Dr_Enfermo)
Website: https://github.com/DrEnfermo/Winscalator.git
'''
class SystemInfo:

        def __init__(self, hostname, osName, osVersion, manufacturer, osConfig,
                osBuildType, regOwner, regOrganization, productID,
                originalInstallDate, sysBootTime, sysManufacturer,
                sysModel, sysType, processors, biosVer, winDir, sysDir,
                bootDev, sysLocale, inputLocale, timeZone, totalPhysMem,
                availablePhysMem, vMemMaxSize, vMemAvailable, vMemInUse,
                pageFileLoc, domain, logonServer, hotfixes,
                networkCards, hypervReq, lastUpdateInThreeMonths='', activeUsers=[], services=[], processes=[], schtasks=[], enabledUAC=None, UAClevel='', wificredentials=[]):
                # Instance Attributes
                self.hostname = hostname
                self.osName = osName
                self.osVersion = osVersion
                self.manufacturer = manufacturer
                self.osConfig = osConfig
                self.osBuildType = osBuildType
                self.regOwner = regOwner
                self.regOrganization = regOrganization
                self.productID = productID
                self.originalInstallDate = originalInstallDate
                self.sysBootTime = sysBootTime
                self.sysManufacturer = sysManufacturer
                self.sysModel = sysModel
                self.sysType = sysType
                self.processors =  processors
                self.biosVer = biosVer
                self.winDir = winDir
                self.sysDir = sysDir
                self.bootDev = bootDev
                self.sysLocale = sysLocale
                self.inputLocale = inputLocale
                self.timeZone = timeZone
                self.totalPhysMem = totalPhysMem
                self.availablePhysMem = availablePhysMem
                self.vMemMaxSize = vMemMaxSize
                self.vMemAvailable = vMemAvailable
                self.vMemInUse = vMemInUse
                self.pageFileLoc = pageFileLoc
                self.domain = domain
                self.logonServer = logonServer
                self.hotfixes = hotfixes
                self.lastUpdateInThreMonths = lastUpdateInThreeMonths
                self.networkCards = networkCards
                self.hypervReq = hypervReq
                self.activeUsers = activeUsers
                self.services = services
                self.processes = processes
                self.schtasks = schtasks
                self.enabledUAC = enabledUAC
                self.UAClevel = UAClevel
                self.wificredentials = wificredentials

        def __str__(self):
                return str(self.__dict__)

        def asdict(self):
                return {'osName' : self.osName,
                        'osVersion': self.osVersion,
                        'manufacturer': self.manufacturer,
                        'osConfig': self.osConfig,
                        'osBuildType': self.osBuildType,
                        'regOwner': self.regOwner,
                        'regOrganization': self.regOrganization,
                        'productID': self.productID,
                        'originalInstallDate': self.originalInstallDate,
                        'sysBootTime': self.sysBootTime,
                        'sysManufacturer': self.sysManufacturer,
                        'sysModel': self.sysModel,
                        'sysType': self.sysType,
                        'processors': self.processors,
                        'biosVer': self.biosVer,
                        'winDir': self.winDir,
                        'sysDir': self.sysDir,
                        'bootDev': self.bootDev,
                        'sysLocale': self.sysLocale,
                        'inputLocale': self.inputLocale,
                        'timeZone': self.timeZone,
                        'totalPhysMem': self.totalPhysMem,
                        'availablePhysMem': self.availablePhysMem,
                        'vMemMaxSize': self.vMemMaxSize,
                        'vMemAvailable': self.vMemAvailable,
                        'vMemInUse': self.vMemInUse,
                        'pageFileLoc': self.pageFileLoc,
                        'domain': self.domain,
                        'logonServer': self.logonServer,
                        'hotfixes': self.hotfixes,
                        'networkCards': self.networkCards,
                        'hypervReq': self.hypervReq}

        def get_architecture(self):
                if self.sysType.contains('64') : return "64"
                else : "32"

        def get_cmdlang(self):
                try:
                        #print(self.sysLocale.split(";")[0].split('-')[0])
                        return self.sysLocale.split(";")[0].split('-')[0]
                except:
                        return 'en'

        def get_processors_list(self):
                if len(self.processors) > 0 and self.processors.index(',') != -1 :
                        only_processors = self.processors[self.processors.find(',')+1: len(self.processors)-1].replace('[','').replace(']','')
                        processors_list = dict((int(i.strip()), j.strip()) for i,j in (l.split(':')
                                        for l in only_processors.split(',')))
                        #print(processors_list)
                else:
                       processors_list = ""
                return processors_list

        def get_patches_list(self):
                if len(self.hotfixes) > 0 and self.hotfixes.index(',') != -1 :
                        only_patches = self.hotfixes[self.hotfixes.find(',')+1: len(self.hotfixes)-1].replace('[','').replace(']','')
                        patches_list = dict((int(i.strip()), j.strip()) for i,j in (l.split(':')
                                        for l in only_patches.split(',')))
                        #print(patches_list)
                else:
                        patchs_list = ""
                return patches_list

        def get_network_interfaces_list(self):
                """TODO: use a dictionary for include different IPs, and a list for the interfaces.
                """
                only_nics = self.networkCards[self.networkCards.find(',')+1: len(self.networkCards)-1].replace('[','').replace(']','')
                network_interfaces_list = only_nics
                #print(network_interfaces_list)
                return network_interfaces_list

        def add_users(self, users_file):
                if os.path.exists(users_file) and os.path.isfile(users_file):
                        with open(users_file, newline='', encoding='cp850') as f:
                                reader = csv.reader(f)
                                for row in reader:
                                        if len(row) > 0 :
                                                # print('user: ' + str(row[2]))
                                                # print('sid: ' + str(row[6]))
                                                # print('passwordchangeable: '+ str(row[3]))
                                                # print('passwordexpires: ' + str(row[4]))
                                                # print('passwordrequired: ' +str(row[5]))

                                                if bool(row[3]) == True:
                                                        passwordchangeable = True
                                                else:
                                                        passwordchangeable = False

                                                if len(row[4])>0 and bool(row[4]==True):
                                                        passwordexpires = True
                                                else:
                                                        passwordexpires = False


                                                if bool(row[5]) == True:
                                                        passwordrequired = True
                                                else:
                                                        passwordrequired = False


                                                active_user = UserInfo(str(row[2]),str(row[6]),True,passwordchangeable, passwordexpires, passwordrequired, None,
                                                                [],[],[],[],[],'')
                                                self.add_user(active_user)
                                                #print(active_user)

        def add_user(self, active_user):
                self.activeUsers.append(active_user)

        def print_users(self):
                for user in self.activeUsers:
                        print(formatting.white_b({'name' : user.name, 'sid' : user.sid,
                                'passwordchangeable' : user.passwordchangeable,
                                'passwordexpires' : user.passwordexpires,
                                'passwordrequired' :user.passwordrequired }))

        def add_services(self, services_file):
                if os.path.exists(services_file) and os.path.isfile(services_file):
                        with open(services_file, newline='', encoding='cp850') as f:
                                #reader = csv.DictReader(f, quotechar="'")
                                reader = csv.reader(f,  delimiter=',', quotechar="'")
                                for row in reader:
                                        if len(row) > 0 :
                                                # print('name: ' + str(row[1]))
                                                # print('pid: ' + str(row[3]))
                                                # print('startName: ' + str(row[4]))
                                                # print('state: ' +str(row[5]))
                                                # print('status: ' +str(row[6]))
                                                # print('pathName: ' + str(row[2]))
                                                service = ServiceInfo(str(row[1]),int(row[3]),str(row[4]),str(row[5]),str(row[6]),str(row[2]),[])
                                                self.add_service(service)

        def add_service(self, service):
                self.services.append(service)

        def get_service(self, service):

                for svc in self.services:
                        if svc.name == service.name and svc.pid == service.pid:
                                return svc
                return None

        def print_services(self):
                for service in self.services:
                        print(formatting.white_b(service))

        def get_noWin32Services(self):
                noWin32services = []
                for service in self.services:
                        if service.is_win32_path():
                                noWin32services.append(service)
                return noWin32services

        def get_noWin32Paths(self):
                noWin32paths = []
                for service in self.get_nonWin32services():
                       noWin32paths.append(service.asdict())
                       #noWin32paths.append('{\'name\':\'' + service.name + '\', \'startName\':\'' +  service.startName + '\', \'pathName\':\'' +service.pathName + '\'}')
                return noWin32paths

        def print_noWin32services(self):
                for service in self.get_noWin32Services():
                        print(formatting.white_b(service))

        def get_servicesWithSpacesInUnquotedPaths(self):
                serviceswithupws = []
                for service in self.get_noWin32Services():
                        if service.is_unquoted_path() :
                                if " " in str(service.pathName):
                                        serviceswithupws.append(service)
                return serviceswithupws

        def get_unquotedServicePathsWithSpaces(self):
                uspws = []
                for service in self.get_servicesWithSpacesInUnquotedPaths():
                        uspws.append(service.asdict())
                        #uspws.append('{\'name\':\'' + service.name + '\', \'startName\':\'' +  service.startName + '\', \'pathName\':\'' +service.pathName + '\'}')
                return uspws


        def print_servicesWithSpacesInUnquotedPaths(self):
                for servicewithupws in self.get_servicesWithSpacesInUnquotedPaths():
                        print(formatting.white_b(servicewithupws))

        def add_svcpermissions(self, svcpermissions_file):
                if os.path.exists(svcpermissions_file) and os.path.isfile(svcpermissions_file):
                        with open(svcpermissions_file, newline='', encoding='cp850') as f:
                                #reader = csv.DictReader(f, quotechar="'")
                                lines = f.readlines()
                                #print(len(lines))
                                for i in range(0, len(lines)):
                                        row = lines[i]
                                        if len(row) > 1 :
                                                # print (str(len(row)))
                                                # print("LINE:")
                                                # print(row)
                                                # print(not str(row).startswith(' '))
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
                                                                        for svc in self.services:
                                                                                # try:
                                                                                #         if isinstance(currentservice, ServiceInfo):
                                                                                #                 print(currentservice)
                                                                                #                 input()
                                                                                # except NameError: pass
                                                                                currentservice = None
                                                                                del currentservice

                                                                                if len(str(svc.pathName)) > 0:
                                                                                        if (('"%s",' % str(svc.name).upper()) in str(row).upper() and
                                                                                                str(svc.pathName).upper() in str(row).upper()):
                                                                                                # Including the new service if path permissions are present...
                                                                                                # print('- NEW SERVICE:')
                                                                                                # print(svc)
                                                                                                # print(str(svc.name.upper()))
                                                                                                # print(str(svc.pathName.upper()))
                                                                                                # print(str(row).upper())
                                                                                                currentservice = svc
                                                                                                break
                                                        else:
                                                                # process permissions from first line (path included)...
                                                                try:
                                                                        if isinstance(currentservice, ServiceInfo):
                                                                                # print(str(currentservice.name.upper()))
                                                                                # print(str(currentservice.pathName.upper()))
                                                                                # print(str(row).upper())
                                                                                perm = str(row).upper().replace(str(currentservice.pathName).upper(), '').strip()
                                                                                # print('- Adding perm %s' % perm)
                                                                                if perm not in currentservice.pathPermissions:
                                                                                        currentservice.add_permission(perm)
                                                                except NameError: pass
                                                else:
                                                        try:
                                                                if isinstance(currentservice, ServiceInfo):
                                                                        #process permissions for the rest of permissions
                                                                        # print('- THE SAME SERVICE:')
                                                                        #print(currentservice)
                                                                        perm = str(row).strip()
                                                                        if perm not in currentservice.pathPermissions:
                                                                                # print('- Adding perm %s' % perm)
                                                                                currentservice.add_permission(perm)
                                                        except NameError: pass
                                        # try:
                                        #         if isinstance(currentservice, ServiceInfo):
                                        #                 print(currentservice)
                                        # except NameError: pass


        def print_svcpermissions(self):
                for svc in self.services:
                        if len(svc.pathPermissions) > 0:
                                print(formatting.white_b(svc.asdict()))

        def add_processes(self, processes_file):
                if os.path.exists(processes_file) and os.path.isfile(processes_file):
                        with open(processes_file, newline='', encoding='cp850') as f:
                                reader = csv.reader(f)
                                for row in reader:
                                        if len(row) > 0 :
                                                #print('name: ' + str(row[1]))
                                                #print('pid: ' + str(row[43]))
                                                #print('executablepath: ' + str(row[23]))
                                                #print('owner: ' + str(row[69]))
                                                process = ProcessInfo(str(row[1]),int(row[43]),str(row[23]),str(row[69]))
                                                self.add_process(process)
                                                print(formatting.white_b(process))

        def add_process(self, process):
                self.processes.append(process)

        def print_processes(self):
                for process in self.processes:
                        print(formatting.white_b(process))

        def add_schtasks(self, schtasks_file):
                if os.path.exists(schtasks_file) and os.path.isfile(schtasks_file):
                        with open(schtasks_file, newline='', encoding='cp850') as f:
                                reader = csv.reader(f)
                                for row in reader:
                                        if len(row) > 0 :
                                                # print('name: ' + str(row[0]))
                                                # print('path: ' + str(row[1]))
                                                # print('status: ' + str(row[2]))
                                                schtask = SchTaskInfo(str(row[0]),str(row[1]),str(row[2]))
                                                self.add_schtask(schtask)

        def add_schtask(self, schtask):
                self.schtasks.append(schtask)

        def print_schtasks(self):
                for schtask in self.schtasks:
                        print(formatting.white_b(schtask))


        def add_wificredentials(self, wifipasswords_file, config_locale_section):
                if os.path.exists(wifipasswords_file) and os.path.isfile(wifipasswords_file):
                        with open(wifipasswords_file, newline='', encoding='cp850') as f:
                                lines = f.readlines()
                                ssidname = ''
                                password = ''
                                wificred = None
                                for i in range(0, len(lines)):
                                        row = lines[i]
                                        # print(row)
                                        if len(row) > 1 :
                                                if str(config_locale_section['ssid_name']).upper() in str(row).strip().split(':')[0].upper():
                                                        # print('ssid: ' + str(row).strip().split(':')[1])
                                                        ssidname = str(row).strip().split(':')[1]
                                                        continue

                                                if str(config_locale_section['wificontent']).upper() in str(row).strip().split(':')[0].upper():
                                                        # print('ssid: ' + str(row).strip().split(':')[1])
                                                        password = str(row).strip().split(':')[1]
                                                        continue

                                                if i != 0 and str(config_locale_section['ssid_number']).upper() in str(row).strip().split(':')[0].upper():
                                                        if isinstance(wificred, PasswordInfo):
                                                                del wificred
                                                        wificred = PasswordInfo(ssidname,password)
                                                        ssidname = ''
                                                        password = ''
                                                        self.add_wificred(wificred)

        def add_wificred(self, wificred):
                self.wificredentials.append(wificred)

        def print_wificredentials(self):
                for wificred in self.wificredentials:
                        print(formatting.white_b(wificred))

