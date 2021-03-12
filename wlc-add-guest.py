#!/usr/bin/env python2
# 20210110, Ing. Ondrej DURAS (dury), Orange Slovensko a.s. ,GPL2
#=vim high Comment ctermfg=brown

## MANUAL ############################################################# {{{ 1

VERSION = "2021.031201"
MANUAL  = """
NAME: Add Guest User on WLC
FILE: wlc-add-guest.py

DESCRIPTION:
  Script to provide a guest wifi access for corporate visitors.
  It creates a guest user onto Wireless Lan Controller.
  Added user expires within 24 hours.
  Then it is deleted authomatically by WLC.

  
SYNTAX:
  wlc-add-guest.pyc -u <username> -p <password>
  wlc-add-guest.pyc -a
  wlc-add-guest.pyc -l
  wlc-add-guest.pyc -c

USAGE:
  wlc-add-guest.py -u Janko.Hrasko -p Zelena_Fazul@

  wlc-add-guest.py -l
    Anicka.Dusickova
    Janko.Hrasko
    Marienka.Hraskova
    Striga.Pernikova

  wlc-add-guest.py -a
    WLC IP Adress ......... : 10.111.222.111
    WLC Admin Login ....... : admin
    WLC Admin Password .... : *******
    WLAN ID ............... : 8
    ---
    Script has been authorized successfully. 

PARAMETERS:
  -u - guest username. Should be in Firstname.Surname .
  -p - guest user password for his WiFi authentication
  -a - launches an script authorization process
  -l - lists valid WiFi guests (not expired yet)
  -c - shows a configuration file

INSTALL:
  1. download and install python from page listed below
  2. download plink.exe from putty.org listed below
  3. ensure the paths to python.exe and plink.exe in environment.
  4. change internal key (below INTERNAL_KEY=<any big number>)
  5. compile a script wlc-add-guest.py into wlc-add-guest.pyc
     python -m compileall
  6. delete plain script wlc-add-guest.py
  7. ask WLC operation team for the script authorization

NOTICE:
  Before the usage, this script should be compiled
  into any kind of binary (executable/bytecode) form,
  as to protect the algorithm of password calculation.
  Script does not store any login or password.
  During the script authorization it generates and
  stores a random key, used for password calculation.

SEE ALSO: 
  https://www.python.org/ftp/python/2.7.17/python-2.7.17.msi
  https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe
  https://www.putty.org/
  https://github.com/ondrej-duras/

VERSION: %s
""" % (VERSION)

####################################################################### }}} 1
## GLOBAL modules and variables ####################################### {{{ 1

import sys
import os
import re
import json
import time
import getpass
import random
import socket
from   uuid import getnode as getmac
import hashlib
import base64


CONFIG={}  # script CONFIGuration structure
AUTHCODE_INTERNAL = 536034627567673L 

####################################################################### }}} 1
## CONFIG handling #################################################### {{{ 1


def configFileName(filename=str(__file__) + ".json"):
  if re.match("\S+\.(exe|py|pyc)\.json$",filename):
     filename = re.sub("\.(exe|py|pyc)\.json$",".json",filename)
  return filename


def configSave(filename=configFileName()):
  global CONFIG
  fh = open(filename,"w")
  fh.write(json.dumps(CONFIG,sort_keys=True,indent=2))
  fh.close()


def configLoad(filename=configFileName()):
  global CONFIG
  if not os.path.isfile(filename):
    CONFIG={}
    return False
  fh = open(filename,"r")
  CONFIG = json.loads(fh.read())
  fh.close()
  return True
  

####################################################################### }}} 1
## AUTHORIZATION ###################################################### {{{ 1


def pwaScriptID(filename=__file__):
  sf=open(filename,"r")
  sfdata=sf.read()
  sf.close()
  sum = hashlib.sha1()
  sum.update(sfdata)
  return base64.b32encode(sum.digest())[3:13]


# fqdn=socket.getfqdn(socket.gethostbyname(socket.gethostname()))
def pwaAutoIdentity():
  authbase = pwaScriptID() + "\\"
  try: 
    authbase += os.environ['USERDOMAIN']+"\\"
  except:
    pass
  authbase += socket.gethostname()+"\\"
  authbase += socket.gethostbyname(socket.gethostname()) + "\\"
  authbase += getpass.getuser()+"\\"
  authbase += str(getmac())
  return authbase


def pwaAutoLogin(identity=pwaAutoIdentity()):  # pwaRobot()
  return "AUTO" + base64.b32encode(hashlib.sha1(identity).digest())[3:10]

def pwaAutoPassword(identity=pwaAutoIdentity()):  # pwaToken()
  global CONFIG,AUTHCODE_INTERNAL
  paswrc = str(AUTHCODE_INTERNAL) + str(CONFIG["wlan"])
  paswrc += identity + str(CONFIG["exkey"])
  return base64.b64encode(hashlib.sha1(paswrc).digest())[3:23]


def wlcAuthorize():
  global CONFIG
  random.seed()
  # collecting session details
  host  = raw_input(      "WLC IP address or Hostname ..... : ")
  wlan  = raw_input(      "WLC WLAN ID (number) ........... : ")
  auser = raw_input(      "WLC Admin Login ................ : ")
  apasw = getpass.getpass("WLC Admin Password ............. : ")
  exkey = random.randrange(10000000000L,99999999999L)

  # Saving configuration
  CONFIG["exkey"] = exkey
  CONFIG["wlan"]  = wlan
  CONFIG["host"]  = host
  configSave()
  
  # Preparing technicalities for SSH session 
  xuser = pwaAutoLogin()
  xpasw = pwaAutoPassword()
  command="plink.exe -no-antispoof -batch -ssh -l %s %s" % (auser,host)

  #> Tu pokracovat upravou SSH relacie
  # Opening and authenticating the SSH session with the WLC
  stdin,stdout = os.popen4(command)
  stdin.write(auser + "\r") # login is provided twice ... :-)
  stdin.write(apasw + "\r") # password (authentication method=none, then chat
  stdin.write("config paging disable\r") # disabling --more--

  # Pushing activity
  stdin.write("show sysinfo\r")   # AirOS version
  stdin.write("show inventory\r") # Harware inventory
  stdin.write("show wlan summary" + "\r")     # or anything else

  # Logout and session termination
  stdin.write("logout\r")   # command to exit
  stdin.write("N\n")        # do not write configuration
  stdin.close()             # that point realy starts the session
  data=stdout.read()        # read everything in single string
  print data #DEBUG
  stdout.close()            # closing SSH session
  return True

####################################################################### }}} 1
## GUEST handling ##################################################### {{{ 1

####################################################################### }}} 1
## MAIN ############################################################### {{{ 1

if __name__ == "__main__":
  argct = len(sys.argv)
  if argct < 2: print MANUAL; exit()
  argix = 1
  while(argix < argct):
    argx = sys.argv[argix]; argix += 1
    if argx in ("-a","--authorize"):
       wlcAuthorize()
      
####################################################################### }}} 1
# --- end ---

