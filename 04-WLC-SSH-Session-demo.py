#!/usr/bin/env python2
#=vim high Comment ctermfg=brown

VERSION = "2021.031101"
MANUAL  = """
NAME: Simplified SSH Session with WLC
FILE: WLC-SSH-Session-demo.py

DESCRIPTION:
  Demonstrates how to communicate with
  the Cisco Wireless LAN Controller.
  It has been tested on decommissioned devices
  4400,5500.


SEE ALSO: https://github.com/ondrej-duras/

VERSION: %s
""" % (VERSION)


import os
import time
import getpass


def pwaLogin(cred):
  return raw_input("Login("+cred+")> ")

def pwaPassword(cred):
  return getpass.getpass("Passw("+cred+")> ")


def wlcExec(host,cred,action):
  # collecting session details
  user=pwaLogin(cred)
  pasw=pwaPassword(cred)

  # Opening and authenticating the SSH session with the WLC
  command="plink.exe -no-antispoof -batch -ssh -l %s %s" % (user,host)
  stdin,stdout = os.popen4(command)
  stdin.write(user + "\r") # login is provided twice ... :-)
  stdin.write(pasw + "\r") # password (authentication method=none, then chat
  stdin.write("config paging disable\r") # disabling --more--

  # Pushing activity
  stdin.write("show sysinfo\r")   # AirOS version
  stdin.write("show inventory\r") # Harware inventory
  stdin.write(action + "\r")     # or anything else

  # Logout and session termination
  stdin.write("logout\r")   # command to exit
  stdin.write("N\n")        # do not write configuration
  stdin.close()             # that point realy starts the session
  data=stdout.read()        # read everything in single string
  stdout.close()            # closing SSH session
  return data

if __name__ == "__main__":
  print wlcExec(raw_input("Host> "),"user","show wlan summary")


# --- end ---

