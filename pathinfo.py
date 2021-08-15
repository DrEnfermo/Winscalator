#!/usr/bin/python3

'''
File  pathinfo.py
It will retrieve all information about paths on target system.
Author: rtrigo aka Dr.Enfermo (@Dr_Enfermo)
Website: https://github.com/DrEnfermo/Winscalator.git
'''
class PathInfo:
    def __init__(self, pathName, pathPermissions=[]):
        self.pathName = pathName
        self.pathPermissions = pathPermissions

    def __str__(self):
        return str(self.__dict__)

    def add_permission(self, permission):
        self.pathPermissions.append(permission)

    def is_win32_path(self):
        if len(self.pathName) > 0:
            return ("system32" not in str(self.pathName).lower())
        else:
            return False
