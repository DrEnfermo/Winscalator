#!/usr/bin/python3
'''
File formatting.py
Module: formatter module file...
It will perform formatting operations for printing to
messages in several different colors and styles...
Author: R. Trigo aka Dr.Enfermo (@Dr_Enfermo)
Website: https://github.com/DrEnfermo/Winscalator.git
'''
from termcolor import colored
# lambda functions to manage colors with preformatted text...
green = lambda x: colored(x, 'green')
red = lambda x: colored(x, 'red')
blue = lambda x: colored(x, 'blue')
cyan = lambda x: colored(x, 'cyan')
yellow = lambda x: colored(x, 'yellow')
green_b = lambda x: colored(x, 'green', attrs=['bold'])
red_b = lambda x: colored(x, 'red', attrs=['bold'])
blue_b = lambda x: colored(x, 'blue', attrs=['bold'])
cyan_b = lambda x: colored(x, 'cyan', attrs=['bold'])
yellow_b = lambda x: colored(x, 'yellow', attrs=['bold'])
white_b = lambda x: colored(x, 'white', attrs=['bold'])