#!/usr/bin/env python2
#=vim high Comment ctermfg=brown

VERSION = 2021.031101
MANUAL  = """
NAME: Example of JSON Configuration File Handling
FILE: Configuration-Handling-demo.py

DESCRIPTION:
  provides a basic functionality, needed to
  manipulate a script configuration.

  The configuration has as the same name as the script has.
  Differs in extension only, where is an .json extension.

SEE ALSO:
  https://github.com/ondrej-duras/

"""

import json
import re
import os

CONFIG={}  # script CONFIGuration structure

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
  if not os.pathexists(filename):
    CONFIG={}
    return False
  fh = open(filename,"r")
  CONFIG = json.loads(fh.read())
  fh.close()
  return True
  

def configEdit():
  global CONFIG
  print "add <key>=<value>"
  print "del <key>"
  print "show save load filename"
  print "done"
  while(True):
    line=raw_input("json>> ")
    line=re.sub(r"^\s+","",line)
    line=re.sub(r"\s+$","",line)
    cmd = re.search("^\S+",line).group(0)
    if cmd in ("add","let"):
       m = re.search("\S+\s+([-A-Za-z0-9._]+)\s*=\s*(\S.*)$",line)
       if not m:
         print "Syntax Error!"; continue
       CONFIG[m.group(1)] = m.group(2)
       continue
    if cmd in ("del","delete","rm","remove"):
       m = re.search("\S+\s+([-A-Za-z0-9._]+)$",line)
       if not m:
         print "Syntax Error!"; continue
       del CONFIG[m.group(1)]
       continue
    if cmd in ("show","list","dump","display"):
       print json.dumps(CONFIG,sort_keys=True,indent=2)
       continue
    if cmd in ("done","exit","quit"):
       break
    if cmd in ("load"):
       configLoad(); continue
    if cmd in ("save","write"):
       configSave(); continue
    if cmd in ("filename"):
       print configFileName(); continue
         


#a = re.search(r"(\S+)\s+(\S+)","ahoj cau")
#print a.group(0)
#print a.group(1)
#print a.group(2)
#b = re.search(r"\S+","ahoj")
#print b.group(0)

if __name__ == "__main__":
  configEdit()

        
       
    

  
