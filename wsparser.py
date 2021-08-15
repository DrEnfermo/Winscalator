#!/usr/bin/python3
'''
File wsparser.py
Class: WSParser
It will perform parsing operations with the application
configuration file (.ini)
Author: R. Trigo aka Dr.Enfermo (@Dr_Enfermo)
Website: https://github.com/DrEnfermo/Winscalator.git
'''
from configparser import ConfigParser

class WSParser():
    def __init__(self, file, defaultvalue=''):
        self.config_file = file
        self.defaultvalue = defaultvalue
        self.reload()

    def reload(self):
        self.config = ConfigParser()
        self.config.read(self.config_file, encoding='utf-8')

    def read(self, file):
        return self.config.read(file, encoding='utf-8')

    def get(self, section, option, defaultvalue = None):
        self.main_section = section
        try:
            return self.config.get(self.main_section, option)
        except:
            if defaultvalue != None:
                return defaultvalue
            else:
                return self.defaultvalue

    def get_section(self, section):
        self.main_section = section
        return dict(self.config.items(self.main_section))

    def getboolean(self, section, option):
        self.main_section = section
        try:
            return self.config.getboolean(self.main_section, option)
        except:
            return False

    def getfloat(self, section, option):
        self.main_section = section
        try:
            return self.config.getfloat(self.main_section, option)
        except:
            return False

    def getint(self, section, option):
        self.main_section = section
        try:
            return self.config.getint(self.main_section, option)
        except:
            return False

    def has_option(self, section,option):
        self.main_section = section
        try:
            return self.config.has_option(self.main_section, option)
        except:
            return False

