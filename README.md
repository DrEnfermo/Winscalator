# Winscalator
Windows Privilege Escalation Assistant v0.0.1



         __/\__        _____ _   _ ____   ____    _    _        _  _____ ___  ____ /\
         / |/\\ \      / |_ _| \ | / ___| / ___|  / \  | |      / \|_   _/ _ \|  _ |/\|
        / /    \ \ /\ / / | ||  \| \___ \| |     / _ \ | |     / _ \ | || | | | |_) |
       / /      \ V  V /  | || |\  |___) | |___ / ___ \| |___ / ___ \| || |_| |  _ <
  ____/_/        \_/\_/  |___|_| \_|____/ \____/_/   \_|_____/_/   \_|_| \___/|_| \_\
 |_____|
----------------------------------------------------------------------------------------------------------
This tool tries to build different decission trees to assist the researcher/pentester in the
Privilege Escalation stage on Windows Systems, once committed an initial target with a user and
a remote shell. Initially, this tool can run in the attacker's machine and some info will be requested
in order to prepare the available paths or branches to follow till Privilege Escalation will be a success.

# Prerequisities

To run Winscalator it is mandatory to have Python 3 (created with Python 3.9.6) or higher and some python libraries.

You can install these with:

``` python
pip install -r requirements.txt
```
Note: Winscalator works in python 3.9.6. Make sure you run a pip relative to this version.

# Usage

``` python
python Winscalator.py \<PROJECT_NAME\>
```
The parameter is the name of the proyect to create (must be a keyname, with only a word).
It will create a folder under the application path to process all needed information in.

# Examples
