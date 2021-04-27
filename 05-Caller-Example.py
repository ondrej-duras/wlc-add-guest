#!/usr/bin/env python2

VERSION = "2021.042701"
MANUAL  = """
NAME: WLC-ADD-GUEST Caller Example
FILE: 05-Caller-Example.py

DESCRIPTION:
  Example shows how to call wlc-add-guest.pyc program.


USAGE:
  ./05-Caller-Example.py

SEE ALSO:
  https://github.com/ondrej-duras/

VERSION: %s
""" % (VERSION)

import os
import re

def wlcCaller(params):
  WLCTOOL = ""
  if os.path.exists(r"c:\wlc\wlc-add-guest.exe"):
    WLCTOOL=r"c:\wlc\wlc-add-guest.exe"
  elif os.path.exists(r"c:\wlc\wlc-add-guest.pyc"):
    WLCTOOL=r"c:\wlc\wlc-add-guest.pyc"
  else:
    print "Error !"; return
  print WLCTOOL
  stdin,stdout = os.popen4(WLCTOOL + " " + params)
  stdin.close()
  output = stdout.read()
  stdout.close()
  return output

if __name__ == "__main__":
  out1 = wlcCaller(" -u Janko.Hrasko -p Hesielko")
  if not out1:
    print "Create - PASS"
  else:
    print "Create - FAIL %s" % (out1)
  out2 = wlcCaller("-l")
  if "Janko.Hrasko" in out2:
    print "List   - PASS"
  else:
    print "List   - FAIL"



