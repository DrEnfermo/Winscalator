#!/usr/bin/python3
'''
File schtask.py
Class: SchTaskInfo
It will retrieve all information about each scheduled task output.
Author: R. Trigo aka Dr.Enfermo (@Dr_Enfermo)
Website: https://github.com/DrEnfermo/Winscalator.git
'''
class SchTaskInfo:
    # TODO: Populate this class.
        def __init__(self, name, path, state):
                # Instance Attributes
                self.name = name
                self.path = path
                self.state = state

        def __str__(self):
                return str(self.__dict__)