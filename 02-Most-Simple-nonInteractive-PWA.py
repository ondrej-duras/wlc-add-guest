#!/usr/bin/env python2

import sys
import base64

CRED={}

def pwaCred(cred="user",filename="",debug=False):
  global CRED
  if not filename:
     filename = ".cred-"+cred+".txt"
  fh = open(filename)
  fd = fh.readlines()
  CRED[cred]={}
  CRED[cred]["host"]=fd[0].rstrip()
  CRED[cred]["user"]=fd[1].rstrip()
  CRED[cred]["pasw"]=base64.b32decode(fd[2].rstrip())
  if debug:
    print "Host ....... %s" % (CRED[cred]["host"])
    print "User ....... %s" % (CRED[cred]["user"])
    print "Pass ....... %s" % (CRED[cred]["pasw"])  #PLAIN!
  fh.close()


def pwaHost(cred="user"):
  global CRED
  return CRED[cred]["host"]

def pwaLogin(cred="user"):
  global CRED
  return CRED[cred]["user"]

def pwaPassword(cred="user"):
  global CRED
  return CRED[cred]["pasw"]
  

def pwaEncrypt(pasw):
  return base64.b32encode(pasw)

if __name__ == "__main__":
  if len(sys.argv) > 1:
     print pwaEncrypt(sys.argv[1])
     exit()
  #pwaCred()
  pwaCred("user","",True)

