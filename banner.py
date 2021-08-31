#!/usr/bin/python3

import formatting

'''
File banner.py
Class: Banner
It will show the application banner.
Author: R. Trigo aka Dr.Enfermo (@Dr_Enfermo)
Website: https://github.com/DrEnfermo/Winscalator.git
'''
class Banner:

    # function to display the banner and info related to app...
    def __init__(self, fulltitle, filename):
        # text to display under the banner...
        self.bannertext = '\n\n'
        self.bannertext = formatting.green_b(fulltitle)
        self.bannertext += formatting.yellow('\n\n[*]        By:')
        self.bannertext += formatting.green_b('    R. Trigo, ')
        self.bannertext += formatting.yellow(' Aka.\'Dr. Enfermo\'')
        self.bannertext += formatting.cyan_b(' (@drenfermo)')
        self.bannertext += formatting.yellow('                     [*]\n\n')
        self.bannertext += formatting.yellow('[*]        USAGE: ')
        self.bannertext += formatting.yellow('python \'')
        self.bannertext += formatting.green_b(filename)
        self.bannertext += formatting.green_b(' <PROJECT_NAME> [-t]')
        self.bannertext += formatting.yellow('\'                   [*]\n')
        self.bannertext += formatting.green_b('                          -t: Target machine is where assistant is running.\n')
        self.bannertext += formatting.yellow('[*]                       (CTRL + C to EXIT PROGRAM) ')
        self.bannertext += formatting.yellow('                           [*]\n')

        # banner to display...
        self.banner = '\n\n'
        self.banner += """

        __/\__       _____ _   _ ____   ____    _    _        _  _____ ___  _____ /\\
        / /\ \      / |_ _| \ | / ___| / ___|  / \  | |      / \|_   _/ _ \|  _  |/\|
       / /  \ \ /\ / / | ||  \| \___ \| |     / _ \ | |     / _ \ | || | | | |_) |
      / /    \ V  V /  | || |\  |___) | |___ / ___ \| |___ / ___ \| || |_| |  _ <
 ____/_/      \_/\_/  |___|_| \_|____/ \____/_/   \_|_____/_/   \_|_| \___/|_| \_\\
|_____|

        """

    def __str__(self):
        return formatting.green_b(self.banner) + self.bannertext