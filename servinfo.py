#!/usr/bin/python3
'''
File servinfo.py
Class: ServiceInfo
It will retrieve all information about each service output.
Author: R. Trigo aka Dr.Enfermo (@Dr_Enfermo)
Website: https://github.com/DrEnfermo/Winscalator.git
'''
class ServiceInfo:

        def __init__(self, name, pid, startName, state, status, pathName, pathPermissions=[]):
                # Instance Attributes
                self.name = name
                self.pid = pid
                self.startName = startName
                self.state = state
                self.status = status
                #TODO: Use pathInfo class for these properties in services...
                self.pathName = pathName
                self.pathPermissions = pathPermissions

        def __str__(self):
                return str(self.__dict__)

        def asdict(self):
                return {'name' : self.name, 'pid' : self.pid, 'startName' : self.startName, 'pathName' : self.pathName, 'pathPermissions' : self.pathPermissions}

        def is_win32_path(self):
                if len(self.pathName) > 0:
                    return ("system32" not in str(self.pathName).lower())
                else:
                    return False

        def is_unquoted_path(self):
                if len(self.pathName) > 0:
                    return not str(self.pathName).startswith('"')
                else:
                    return False

        def is_running(self):
                if len(self.state) > 0 :
                    return ("runnning" in str(self.state).lower())
                else:
                    return False

        def owner_is_system(self):
                if len(self.startName) > 0 :
                    return ("localsystem" in str(self.startName).lower())
                else:
                    return False

        def add_permission(self, permission):
                self.pathPermissions.append(permission)