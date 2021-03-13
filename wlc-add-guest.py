#!/usr/bin/env python2
# 20210110, Ing. Ondrej DURAS (dury), Orange Slovensko a.s. ,GPL2
#=vim color desert
#=vim high pythonBuiltin ctermfg=darkcyan
#=vim high Comment ctermfg=darkgreen
#=vim syntax match Comment /^\s*#.*$/

## MANUAL ############################################################# {{{ 1

VERSION = "2021.031301"
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

# List of modules used in this script
# all modules are native - included in installation file python-2.7.17.msi
# ... so none needs to be added via pip utility. 
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


CONFIG = {}  # script CONFIGuration structure / stored .JSON in configuration file
AUTHCODE_INTERNAL = 536034627567673L # authorization code of the script instance

# CLI parameters, collected by cliParameters() handled by takeAction()
VUSER  = ""  # visitor's username given trough CLI
VPASW  = ""  # visitor's password -//-
VDESC  = ""  # visitor's description
ACTION = ""  # action / activity, taken based on collection of CLI parameters


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
## WLC SSH Sessions ################################################### {{{ 1

def wlcExec(host,user,pasw,action,save="N"):
  # Opening and authenticating the SSH session with the WLC
  command="plink.exe -no-antispoof -batch -ssh -l %s %s" % (user,host)
  stdin,stdout = os.popen4(command)
  stdin.write(user + "\r") # login is provided twice ... :-)
  stdin.write(pasw + "\r") # password (authentication method=none, then chat
  stdin.write("config paging disable\r") # disabling --more--

  # Pushing activity
  #stdin.write("show sysinfo\r")   # AirOS version
  #stdin.write("show inventory\r") # Harware inventory
  #stdin.write("show wlan summary" + "\r")     # or anything else
  for line in action.splitlines():
    stdin.write(line + "\r")

  # Logout and session termination
  stdin.write("logout\r")   # command to exit
  stdin.write(save + "\n")  # do not write configuration
  stdin.close()             # that point realy starts the session
  data = ""                 # read everything in single string
  for line in stdout.readlines():
    if re.match("User:",line):     continue # removes confidetial parts of the session
    if re.match("Password:",line): continue
    data += line.rstrip() + "\n"
  stdout.close()            # closing SSH session
  return data               # returns output of the session

####################################################################### }}} 1
## AUTHORIZATION ###################################################### {{{ 1

# everything related to authorization of this script
# includes also AutoLogin and AutoPassword calculations used
# byt script to access the controller.


# Provides an uniqueID of the script
# if script changes (even a comment within the script), then
# the script's ID changes too ...and then it requeres re-authorization
def pwaScriptID(filename=__file__):
  sf=open(filename,"r")
  sfdata=sf.read()
  sf.close()
  sum = hashlib.sha1()
  sum.update(sfdata)
  return base64.b32encode(sum.digest())[3:13]

# All details that should be enought to authorize this script.
# They are intented to be used for remote authorization within later versions.
# # fqdn=socket.getfqdn(socket.gethostbyname(socket.gethostname()))
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

# describes a source of authomated user HOSTNAME-LOGIN where from
# an activities have come
def pwaAutoDescription():
    return socket.gethostname() + "-" + getpass.getuser()

# Authorized Login name, used to access the controller
def pwaAutoLogin(identity=pwaAutoIdentity()):  # pwaRobot()
  return "AUTO" + base64.b32encode(hashlib.sha1(identity).digest())[3:10]

# Authorized Password, used to access the controller
def pwaAutoPassword(identity=pwaAutoIdentity()):  # pwaToken()
  global CONFIG,AUTHCODE_INTERNAL
  paswrc = str(AUTHCODE_INTERNAL) + str(CONFIG["wlan"])
  paswrc += identity + str(CONFIG["exkey"])
  return base64.b64encode(hashlib.sha1(paswrc).digest())[3:23]

# Provides whole action of the Script Authorization
def wlcAuthorize():
  global CRED,CONFIG
  random.seed()
  # collecting session details
  host  = raw_input(      "WLC IP address or Hostname ..... : ")
  auser = raw_input(      "WLC Admin Login ................ : ")
  apasw = getpass.getpass("WLC Admin Password ............. : ")
  wlan  = raw_input(      "WLC WLAN ID (number) ........... : ")
  exkey = random.randrange(10000000000L,99999999999L)

  # Saving configuration
  CONFIG["exkey"] = exkey
  CONFIG["wlan"]  = wlan
  CONFIG["host"]  = host
  configSave()
  print "Configuration saved."
 
  # Preparing technicalities for SSH session 
  xuser = pwaAutoLogin()
  xpasw = pwaAutoPassword()
  xdesc = pwaAutoDescription() 
  # config mgmtuser add AUTO12341234 Hello.Hello+ read-write ScriptID12341234-Automat
  # show mgmtuser
  # config mgmtuser delete AUTO12341234
  action = "config mgmtuser add %s %s read-write %s\n" % (xuser,xpasw,xdesc)
  print "Connecting WLC ..."
  wlcExec(host,auser,apasw,action,"y")
  print "Stript registered as %s" % (xuser)
  print "Checking Authentication..."
  data = wlcExec(host,xuser,xpasw,"show mgmtuser\n")
  if xuser in data:
    print "Script has been authorized successfully."
    return True
  else:
    print "WARNING: Something wrong has happened."
    return False

####################################################################### }}} 1
## GUEST handling ##################################################### {{{ 1

# procedures handling all visitors' WiFi accesses

# Adds new visitor's account to access corporate WiFi
def wlcAddGuest(vuser,vpasw,vdesc=""):
  configLoad()
  host = CONFIG["host"]
  wlan = CONFIG["wlan"]
  xuser= pwaAutoLogin()
  xpasw= pwaAutoPassword()
  if not vdesc:
    vdesc = "by" + xuser
  if not (host and xuser and xpasw and wlan):
     print "Error: Script Configuration Issue !"
     return False
  action  = "config netuser add %s %s wlan %s " % (vuser,vpasw,wlan)
  action += "userType guest lifetime 86400 description %s\n" % (vdesc)
  action += "show netuser summary\n"
  data = wlcExec(host,xuser,xpasw,action)
  return True


# Lists still valid viritors' accesses
def wlcListGuests():
  configLoad()
  host = CONFIG["host"]
  xuser= pwaAutoLogin()
  xpasw= pwaAutoPassword()
  if not (host and xuser and xpasw):
     print "Error: Script Configuration Issue !"
     return False
  action  = "show netuser summary\n";
  data = wlcExec(host,xuser,xpasw,action)
  if xpasw in data:
    print "Error: "
    print "  Temporary error in SSH communication."
    print "  Don't worry. Try again."
  else:
    print data
  return True


####################################################################### }}} 1
## ACTIONS ############################################################ {{{ 1

# checks parameters given by command line / semantic check
# then calls appropriate procedure to take an action

def takeAction():
  global VUSER,VPASW,VDESC,ACTION

  # adds visitor's access to WiFi
  if ACTION == "addGuest":
     if not (VUSER and VPASW):
        print "Error: addGuest: user (-u) and password (-p) must be provided !"
     wlcAddGuest(VUSER,VPASW,VDESC)
     exit()

  # authorizes this script. Makes its own admin account with 
  # the calculated login and password.
  # Access password is not stored anywhere.
  if ACTION == "authorizeScript":
     wlcAuthorize()
     exit()

  # provides an list of valid visitors' accounts
  if ACTION == "listGuests":
     wlcListGuests()
     exit()

####################################################################### }}} 1
## CLI interface - handling CLI parameters ############################ {{{ 1

# collects command-line parameters
# and does their syntax check
# also it assumes an ACTION which would be taken

def cliParameters():
  global VUSER,VPASW,VDESC,ACTION
  argct = len(sys.argv)
  if argct < 2: print MANUAL; exit()
  argix = 1
  while(argix < argct):
    argx = sys.argv[argix]; argix += 1

    if argx in ("-a","--authorize"):
       ACTION = "authorizeScript"
       continue

    if argx in ("-l","--list"):
       ACTION = "listGuests"
       continue

    if argx in ("-u","--user"):
       VUSER = sys.argv[argix]; argix += 1
       ACTION = "addGuest" 
       continue

    if argx in ("-p","--password"):
       VPASW = sys.argv[argix]; argix += 1
       ACTION = "addGuest" 
       continue

    if argx in ("-d","--description"):
       VDESC = sys.argv[argix]; argix += 1
       ACTION = "addGuest" 
       continue


####################################################################### }}} 1
## MAIN ############################################################### {{{ 1

# the Main part of the programm
# it should be as short as possible
if __name__ == "__main__":
  cliParameters()
  takeAction()
    
####################################################################### }}} 1
# --- end ---

