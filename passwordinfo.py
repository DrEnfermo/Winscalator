#!/usr/bin/python3
'''
File passwordinfo.py
Class: PasswordInfo
It will retrieve all information about WIFI Passwords.
TODO: Add username and use for retrieve all kind of passwords.
      WifiPass should be only a inherited class from this one...
Author: R. Trigo aka Dr.Enfermo (@Dr_Enfermo)
Website: https://github.com/DrEnfermo/Winscalator.git
'''
class PasswordInfo:

        def __init__(self, ssid, password):
                # Instance Attributes
                self.ssid = ssid
                self.password = password

        def __str__(self):
                return str(self.__dict__)

