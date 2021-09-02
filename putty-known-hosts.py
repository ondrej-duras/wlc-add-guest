#!/usr/bin/env python2
#=vim high comment ctermfg=darkgreen

VERSION = "2021.082502"
MANUAL  = """
NAME: PuTTY Known Hosts utility
FILE: putty-known-hosts.py

DESCRIPTION:
  Manipulates PuTTY Known Hosts base within Windows Registry.

EXAMPLE:
  putty-known-hosts.py -l
  putty-known-hosts.py -s .*sun.*
  putty-known-hosts.py -h ssh-ed25519@22:10.1.1.1
  putty-known-hosts.py -k
  putty-known-hosts.py -d ssh-ed25519@22:10.1.1.1

PARAMETERS:
  -l - lists all known hosts stored in windows registry
  -s - searches for some host in registry (match)
  -h - searches for particular host (best before deleting)
  -k - shows a parent registry key only
  -d - deletes particular host from registry

MAINTEMANCE:
  Backup Operation 
  c:\> reg export HKCU\SOFTWARE\SimonTatham\PuTTY\SshHostKeys PUTTY_SSH_KEYS.txt /y

  PuTTY Full Backup Operation 
  c:\> reg export HKCU\SOFTWARE\SimonTatham\PuTTY\ PUTTY_BACKUP.txt /y

  Restore Known Host public keys only 
  c:\> reg import PUTTY_SSH_KEYS.txt

  Restore whole PuTTY configuration
  c:\> reg import PUTTY_BACKUP.txt

SEE ALSO:
  - PuTTY home site
    https://www.chiark.greenend.org.uk/~sgtatham/putty/
  - this script home site
    https://github.com/ondrej-duras/

VERSION: %s
""" % (VERSION)

import os
import re
import sys

PUTTY  =r"HKCU\SOFTWARE\SimonTatham\PuTTY"
REGKEY =r"HKCU\SOFTWARE\SimonTatham\PuTTY\SshHostKeys"

def getKnownHosts(regex=".*",regkey=REGKEY):
  fh=os.popen(r"reg query %s" % (regkey))
  for line in fh.readlines():
    if not "REG_SZ" in line: continue
    (host,key)=re.split("\s+REG_SZ\s+",line)
    host=re.sub("^\s+","",host)
    if not re.match(regex,host): continue
    print(host)
  fh.close



# C> putty-known-hosts.py -k
# HKCU\SOFTWARE\SimonTatham\PuTTY\SshHostKeys
#
# C> reg delete HKCU\SOFTWARE\SimonTatham\PuTTY\SshHostKeys /v rsa2@22:10.8.51.48
# Delete the registry value rsa2@22:10.8.51.48 (Yes/No)? Y
# The operation completed successfully.
#
# C>                                                                                                                                           


def deleteKnownHost(host):
  global REGKEY
  cmd = r"reg delete " + "\"" + REGKEY + "\"" + " /v " + host
  print(cmd)
  stdin,stdout=os.popen4(cmd)
  stdin.write("Y\r")
  stdin.close()
  out=stdout.read()
  stdout.close()
  print(out)
  
def backupPuTTY(FNAME="PUTTY_FULLBACKUP.txt"):
  fh=os.system(r"reg export HKCU\SOFTWARE\SimonTatham\PuTTY %s /y" % (FNAME))
  print("Written in file '%s'" % (FNAME))
  fh.close()

if __name__ == "__main__":
  if len(sys.argv) < 2 : print MANUAL; exit()
  if sys.argv[1] in ("-l","--list"):   getKnownHosts()
  if sys.argv[1] in ("-s","--search"): getKnownHosts(sys.argv[2])
  if sys.argv[1] in ("-h","--host"):   getKnownHosts(".*","\"" + REGKEY + "\" /v " + sys.argv[2])
  if sys.argv[1] in ("-k","--regkey"): print(REGKEY)
  if sys.argv[1] in ("-b","--backup"): backupPuTTY()
  if sys.argv[1] in ("-d","--delete"): deleteKnownHost(sys.argv[2])

