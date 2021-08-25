#!/usr/bin/env python2
# -*- coding: ascii -*-
# 20210110, Ing. Ondrej DURAS (dury), Orange Slovensko a.s. ,GPL2
#=vim color desert
#=vim high pythonBuiltin ctermfg=darkcyan
#=vim high Comment ctermfg=darkgreen
#=vim syntax match Comment /^\s*#.*$/

## MANUAL ############################################################# {{{ 1

VERSION = "2021.082502"
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
  wlc-add-guest.pyc -u <username> -c

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
  -c - check whether particular username does exist

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
  https://github.com/PowerShell/Win32-OpenSSH/releases
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
VUSER  = ""   # visitor's username given trough CLI
VPASW  = ""   # visitor's password -//-
VDESC  = ""   # visitor's description
ACTION = []   # action / activity, taken based on collection of CLI parameters
DEBUG  = ""   # controlls troubleshooting
HIREST = []   #. 
HIREPL = r"%" #.

# Unable to negotiate with port 22: no matching key exchange method found. 
# Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
SSH_SSH2C = r"ssh.exe -tt -o StrictHostKeyChecking=no -o KexAlgorithms=+diffie-hellman-group1-sha1 -l %s %s"
SSH_PLINK = r"plink.exe -no-antispoof -batch -ssh -l %s %s"
SSH_PLNKH = r"plink.exe -no-antispoof -batch -ssh -hostkey <HOSTKEY> -l %s %s"
SSH_SSH2V = r"ssh.exe -vv -tt -o StrictHostKeyChecking=no -o KexAlgorithms=+diffie-hellman-group1-sha1 -l %s %s"
SSH_PLNKV = r"plink.exe -v -no-antispoof -batch -ssh -l %s %s"
SSH_PLKHV = r"plink.exe -v -no-antispoof -batch -ssh -hostkey <HOSTKEY> -l %s %s"

SSH_VARIANT=[ 
  SSH_SSH2C, # 1 - OpenSSH found in PATH
  SSH_PLINK, # 2 - PLINK found in PATH
  SSH_PLNKH, # 3 - PLINK found in PATH, using particular hostkey
  SSH_SSH2V, # 4 - OpenSSH within verbose troubleshooting mode
  SSH_PLNKV, # 5 - PLINK within troubleshooting mode
  SSH_PLKHV, # 6 - PLINK within troubleshooting mode, using particular hostkey
  "C:\\WINDOWS\\System32\\OpenSSH\\"+SSH_SSH2C, # 7 - Windows native OpenSSH (LibreTSL based)
  "C:\\msys64\\usr\\bin\\"+SSH_SSH2C, # 8 - OpenSSH distributed within msys2.org toolchain
  "C:\\WLC\\"+SSH_SSH2C,    # 9 - specific OpenSSH client
  "C:\\WLC\\OpenSSH\\"+SSH_SSH2C, # 10 - specific OpenSSH client-2
  "C:\\WLC\\"+SSH_PLINK, # 11 - specific PuTTY PLINK 
  "C:\\WLC\\"+SSH_PLNKH  # 12 - specific PuTTY PLINK, using specific hostkey
]



try: # gives a sence when script becomes compiled
  __file__
except:
  __file__ = "wlc-add-guest.exe"

####################################################################### }}} 1
## CONFIG handling #################################################### {{{ 1


def printx(txt):
  global HIREST,HIREPL
  for word in HIREST:
    txt=txt.replace(word,HIREPL)
  print(txt)

def debug(types,txt):
  global DEBUG
  if not DEBUG: return
  types2 = "all." + types
  if not (DEBUG in types2): return
  for line in txt.splitlines():
    printx("#[%s]: %s" % (types,line))

def configFileName(filename=str(__file__) + ".json"):
  if re.match("\S+\.(exe|py|pyc)\.json$",filename):
     filename = re.sub("\.(exe|py|pyc)\.json$",".json",filename)
     debug("config.filename",filename)
  return filename


def configSave(filename=configFileName()):
  global CONFIG
  fh = open(filename,"w")
  fh.write(json.dumps(CONFIG,sort_keys=True,indent=2))
  fh.close()
  debug("config.save",json.dumps(CONFIG,sort_keys=True,indent=2))


def configLoad(filename=configFileName()):
  global CONFIG
  if not os.path.isfile(filename):
    CONFIG={}
    debug("config.load","FILE '%s' NOT FOUND!" % (filename))
    return False
  fh = open(filename,"r")
  CONFIG = json.loads(fh.read())
  fh.close()
  return True


####################################################################### }}} 1
## multiline string handling ########################################## {{{ 1

def txtMatch(pat,txt,empty=0):
  out=""
  for line in txt.splitlines():
    if empty and re.match("^\s*$",line): # includes empty lines (explicit option)
      out += line+"\n"
    if re.match(pat,line):   # includes lines matching pattern
      out += line+"\n"
  return out

def txtFilter(pat,txt,empty=1):
  out=""
  for line in txt.splitlines():
    if empty and re.match("^\s*$",line): continue # cuts out an empty lines (default option)
    if re.match(pat,line): continue  # filters out lines matching pattern
    out += line+"\n"
  return out

def txtCount(txt):
  if txt == None: return 0
  if txt == "": return 0
  return len(txt.splitlines())


def txtGetOption(OPTIONS): # OPTIONS = [ "ssh.exe", "plink.exe" ] : option-1, option-2
  menu = ""
  for inx,text in enumerate(OPTIONS):
    menu += "%3u : %s\n" % (inx+1,text)
  opt = 0
  cto = len(OPTIONS)
  while opt == 0:
    if cto == 0 : break
    print(menu)
    opt = int(raw_input("Option[1-%u]>>> " % (cto)))
    if( (opt>0) and (opt<=cto)):
      return OPTIONS[opt-1] # sucessfull case
  return "" # case of failure

####################################################################### }}} 1
## WLC SSH Sessions ################################################### {{{ 2

def wlcExec(host,user,pasw,action,save="N"):
  global CONFIG, SSH_SSH2C, SSH_PLINK
  # Preparing SSH command
  #command="plink.exe -no-antispoof -batch -ssh -l %s %s" % (user,host)
  #command="ssh  -o StrictHostKeyChecking=no -o KexAlgorithms=+diffie-hellman-group1-sha1 -l %s %s" % (user,host)
  command = CONFIG["ssh"]
  if command[-7:]=="ssh.exe":
    command=command[:-7]+SSH_SSH2C
  if command[-9:]=="plink.exe":
    command=command[:-9]+SSH_PLINK
  command=command % (user,host)
  debug("ssh.command",command)
  debug("ssh.send",action)
  
  # Opening and authenticating the SSH session with the WLC
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
    if pasw in line:               continue
    data += line.rstrip() + "\n"
  stdout.close()            # closing SSH session
  debug("ssh.recv",data)
  return data               # returns output of the session

####################################################################### }}} 1
## AUTHORIZATION ###################################################### {{{ 1

# everything related to authorization of this script
# includes also AutoLogin and AutoPassword calculations used
# byt script to access the controller.
#
# PuTTY registry
# reg export "\HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\SshHostKeys" SSH_KNOWN_HOSTS.txt /y
# reg export "HKCU\SOFTWARE\SimonTatham\PuTTY\SshHostKeys" SSH_KNOWN_HOSTS.txt /y
# reg query "HKCU\SOFTWARE\SimonTatham\PuTTY\SshHostKeys"

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
  #authbase += getpass.getuser()+"\\"
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
  global CONFIG,AUTHCODE_INTERNAL,HIREST
  paswrc = str(AUTHCODE_INTERNAL) + str(CONFIG["wlan"])
  paswrc += identity + str(CONFIG["exkey"])
  paswrc = base64.b64encode(hashlib.sha1(paswrc).digest())[3:23]
  if paswrc not in HIREST:
    HIREST.append(paswrc)
  return paswrc

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
  ssh   = txtGetOption(SSH_VARIANT)

  # Adding a HOSTKEY if required
  if "<HOSTKEY>" in ssh:
    hostkey = raw_input(  "WLC HostKey (aa:bb:cc...) ...... : ")
    ssh.replace("<HOSTKEY>",hostkey)

  # Saving configuration
  CONFIG["exkey"] = exkey
  CONFIG["wlan"]  = wlan
  CONFIG["host"]  = host
  CONFIG["ssh"]   = ssh
  configSave()
  printx("Configuration saved.")
 
  # Preparing technicalities for SSH session 
  xuser = pwaAutoLogin()
  xpasw = pwaAutoPassword()
  xdesc = pwaAutoDescription() 
  # config mgmtuser add AUTO12341234 Hello.Hello+ read-write srcHOST-srcUSER
  # show mgmtuser
  # config mgmtuser delete AUTO12341234
  action  = ""
  action += "config mgmtuser delete %s\n" % (xuser)
  action += "config mgmtuser add %s %s read-write %s\n" % (xuser,xpasw,xdesc)
  printx("Connecting WLC ...")
  wlcExec(host,auser,apasw,action,"y")
  printx("Stript registered as %s" % (xuser))
  printx("Checking Authentication...")
  data = txtMatch("AUTO",wlcExec(host,xuser,xpasw,"show mgmtuser\n"))
  printx(data)
  if xuser in data:
    printx("Script has been authorized successfully.")
    return (True,data)
  else:
    printx("WARNING: Something wrong has happened.")
    return (False,data)

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
     msg="Error: Script Configuration Issue !"
     printx(msg)
     return (False,msg)
  action  = ""
  action += "config netuser delete %s\n" % (vuser)
  action += "config netuser add %s %s wlan %s " % (vuser,vpasw,wlan)
  action += "userType guest lifetime 86400 description %s\n" % (vdesc)
  action += "show netuser summary\n"
  data = wlcExec(host,xuser,xpasw,action)
  return (True,data)



# Lists still valid viritors' accesses
def wlcListGuests(verbose=True):
  configLoad()
  host = CONFIG["host"]
  wlan = CONFIG["wlan"]
  xuser= pwaAutoLogin()
  xpasw= pwaAutoPassword()
  if not (host and xuser and xpasw):
     printx("Error: Script Configuration Issue !")
     return False
  action  = "show netuser summary\n";
  data = wlcExec(host,xuser,xpasw,action)
  if xpasw in data:
    printx("Error: ")
    printx("  Temporary error in SSH communication.")
    printx("  Don't worry. Try again.")
  else:
    if verbose:
      printx(txtMatch(".*WLAN",data))
  return (True,data)


# Check whether particular user has been really created
def wlcCheckGuest(vuser):
  (result,data)=wlcListGuests(False)
  if not result: return result
  output=txtMatch("%s\s+WLAN\s+%d" % (vuser,int(CONFIG["wlan"])),data) 
  if txtCount(output) == 1:
    printx("+>User found")
    return True
  else:
    printx("!>Error: USER NOT FOUND!")
    return (False,output)


####################################################################### }}} 1
## ACTIONS ############################################################ {{{ 1

# checks parameters given by command line / semantic check
# then calls appropriate procedure to take an action

def takeAction():
  global VUSER,VPASW,VDESC,ACTION

  # authorizes this script. Makes its own admin account with 
  # the calculated login and password.
  # Access password is not stored anywhere.
  if ("authorizeScript" in ACTION):
     debug("action.authorize","begin")
     wlcAuthorize()
     debug("action.authorize","end")
     sys.exit()

  # adds visitor's access to WiFi
  if (("addUsername" in ACTION) and ("addPassword" in ACTION)):
     if not (VUSER and VPASW):
        printx("Error: addGuest: user (-u) and password (-p) must be provided !")
        sys.exit()
     debug("action.adduser",VUSER+"/"+VPASW)
     wlcAddGuest(VUSER,VPASW,VDESC)

  # check whether an user has been created
  if ("checkUsername" in ACTION):
     if not VUSER:
       printx("Error: user (-u) must be provided !")
       sys.exit()
     debug("action.checkuser",VUSER)
     wlcCheckGuest(VUSER)

  # provides an list of valid visitors' accounts
  if ("listGuests" in ACTION):
     debug("action.listguests","list")
     wlcListGuests()

  sys.exit()

####################################################################### }}} 1
## CLI interface - handling CLI parameters ############################ {{{ 1

# collects command-line parameters
# and does their syntax check
# also it assumes an ACTION which would be taken

def cliParameters():
  global VUSER,VPASW,VDESC,ACTION,DEBUG
  argct = len(sys.argv)
  if argct < 2: printx(MANUAL); sys.exit()
  argix = 1
  while(argix < argct):
    argx = sys.argv[argix]; argix += 1
    debug("cli.parameter",str("%02u/%02u : %s" % (argix,argct,argx)))

    if argx in ("-a","--authorize"):
       ACTION.append("authorizeScript")
       debug("cli.parameter.authorize","detected")
       continue

    if argx in ("-l","--list"):
       ACTION.append("listGuests")
       debug("cli.parameter.list","detected")
       continue

    if argx in ("-u","--user"):
       VUSER = sys.argv[argix]; argix += 1
       ACTION.append("addUsername")
       ACTION.append("checkUsername")
       debug("cli.parameter.user",VUSER)
       continue

    if argx in ("-p","--password"):
       VPASW = sys.argv[argix]; argix += 1
       ACTION.append("addPassword")
       debug("cli.parameter.pass",VPASW)
       continue

    if argx in ("-c","--check"):
       ACTION.append("checkUsername")
       debug("cli.parameter.check","detected")
       continue


    if argx in ("-d","--description"):
       VDESC = sys.argv[argix]; argix += 1
       ACTION.append("addDescription")
       debug("cli.parameter.desc",VDESC)
       continue

    if argx in ("-v","--verbose","--debug"):
       DEBUG = str(sys.argv[argix]).lower(); argix += 1
       debug("cli.parameter.verbose",DEBUG)
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

