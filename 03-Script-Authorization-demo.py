#!/usr/bin/env python2
# 20210310, Ing. Ondrej DURAS (dury)


VERSION = 2021.031001
MANUAL  = """
NAME: Script Authorization Details
FILE: Script-Authorization-demo.py

DESCRIPTION:
  Provides some idea how to authorize automated scripts.
  Of course, such script must be compiled to protect 
  the password details.

  python -m compileall script.py
  ... will produce a compiled bytecode in file script.pyc

  Authorization Procedure:
  @user> script.pyc --request-authorization
   ... 1. produces an identity string

  @operation> script.pyc --authorize-script
   ... 1. creates one-time authorization account
   ... 2. provides authorization code

  @user> script.pyc --apply-authorization
   ... 1. uses authorization code to generate otp.
   ... 2. creates admin account
   ... 3. deletes one-time authorization account

"""

import os
import hashlib
import base64
import getpass
from uuid import getnode as getmac
import socket


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

AUTHCODE_INTERNAL = "**ChangeMeBeforeCompilation**"
def pwaAutoPassword(extkey,identity=pwaAutoIdentity()):  # pwaToken()
  global AUTHCODE_INTERNAL
  return base64.b64encode(hashlib.sha1(AUTHCODE_INTERNAL + identity + str(extkey)).digest())[3:23]

if __name__ == "__main__":
  print( "AutoIdentity ..... " + pwaAutoIdentity())
  print( "AutoLogin ........ " + pwaAutoLogin())
  print( "AutoPassword ..... " + pwaAutoPassword(891378312))

# --- end ---

