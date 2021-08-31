# Winscalator

Windows Privilege Escalation Assistant v0.0.1

``` bash


         __/\__        _____ _   _ ____   ____    _    _        _  _____ ___  ____ /\
         / |/\\ \      / |_ _| \ | / ___| / ___|  / \  | |      / \|_   _/ _ \|  _ |/\|
        / /    \ \ /\ / / | ||  \| \___ \| |     / _ \ | |     / _ \ | || | | | |_) |
       / /      \ V  V /  | || |\  |___) | |___ / ___ \| |___ / ___ \| || |_| |  _ <
  ____/_/        \_/\_/  |___|_| \_|____/ \____/_/   \_|_____/_/   \_|_| \___/|_| \_\
 |_____|

```

----------------------------------------------------------------------------------------------------------

## About

This tool tries to assist the researcher/pentester/student in the enumeration stages at a Windows machine,
looking for ways to to escalate privileges once committed an initial target with a user and
a remote shell. Initially, this tool can run in the attacker's machine or in the remote machine, and some
info will be requested in order to prepare the available paths or branches to follow till Privilege
Escalation success. The assistant will suggest commands to execute a writable folder in the target.
These commands will generate file outputs that serves to privilege escalation methodology in order
to identify potential ways to escalate.

## Prerequisites

To run Winscalator it is mandatory to have Python 3 (created with Python 3.9.6) or higher and some python libraries.

You can install these with:

``` python
pip install -r requirements.txt
```

Note: Winscalator works in python 3.9.6. Make sure you run a pip relative to this version.

## Usage

``` python
python Winscalator.py \<PROJECT_NAME\> [-t]
```

The first parameter is the name of the proyect to create (must be a keyname, with only a word).
It will create a folder under the application path to process all needed information in.

The optional parameter -t if given, will specify if the assistant is being executed at the same machine that the target.

## Examples

``` bash
python Winscalator.py TEST -t

        __/\__       _____ _   _ ____   ____    _    _        _  _____ ___  _____ /\ 
        / /\ \      / |_ _| \ | / ___| / ___|  / \  | |      / \|_   _/ _ \|  _  |/\|
       / /  \ \ /\ / / | ||  \| \___ \| |     / _ \ | |     / _ \ | || | | | |_) |   
      / /    \ V  V /  | || |\  |___) | |___ / ___ \| |___ / ___ \| || |_| |  _ <    
 ____/_/      \_/\_/  |___|_| \_|____/ \____/_/   \_|_____/_/   \_|_| \___/|_| \_\   
|_____|

        
[*]        Winscalator 0.0.1 ( https://github.com/DrEnfermo/Winscalator.git )   [*]  

[*]        By:    R. Trigo,  Aka.'Dr. Enfermo' (@drenfermo)                     [*]  

[*]        USAGE: python 'Winscalator.py <PROJECT_NAME> [-t]'                   [*]  
                          -t: Target machine is where assistant is running.
[*]                       (CTRL + C to EXIT PROGRAM)                            [*]  


[+]  The name of your project will be:
     TEST

[*] Are you sure to continue? (y/n):  
```

You can skip the steps not needed for the main clasess population
(basically minimal info for system and user in target machine).

Yo will complete each step copying the commands and launching them against
the remote shell in Windows Target machine. If the files are not in the same
machine than the one we're executing the assistant, we will need to copy that
files (or the output result in the remote shell) to the specific file output in
the project's folder (within the application directory).

### Usage's video
