#!/usr/bin/python3
'''
File procinfo.py
Class: ProcessInfo
It will retrieve all information about each process output.
Author: R. Trigo aka Dr.Enfermo (@Dr_Enfermo)
Website: https://github.com/DrEnfermo/Winscalator.git
'''
class ProcessInfo:
    # TODO: Populate this class.
        def __init__(self, name, pid, path, owner):
                # Instance Attributes
                self.name = name
                self.pid = pid
                self.path = path
                self.owner = owner

        def __str__(self):
                return str(self.__dict__)
