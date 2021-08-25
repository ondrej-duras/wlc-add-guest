#!/usr/bin/env python2

import sys
import hashlib


def getDigest(data,method="md5"):
  dx = hashlib.new(method)
  dx.update(data)
  return(dx.hexdigest())

if len(sys.argv) <2:
  print "Usage: is-ascii.py file.txt"
  exit()

FNAME=sys.argv[1]
fh=open(FNAME,"r")
data=fh.readlines()
fh.close()

FFLAG=True
CHARS=0
BELOW=0
ABOVE=0
TABS9=0
CR=0
LF=0
ESC=0
FORMAT="unknown"
CODING="not found"
VIMFF="not found"
XVER="not found"

for ch in "".join(data):
  cx=ord(ch)
  if cx<10  : FFLAG=False; BELOW+=1
  if cx>126 : FFLAG=False; ABOVE+=1
  if cx==9  : TABS9+=1
  if cx==13 : CR+=1
  if cx==10 : LF+=1
  if cx==27 : ESC+=1
  CHARS+=1

if CR == LF == len(data):
  FORMAT = "MS-DOS/Windows"
if (CR < LF) and (LF == len(data)):
  FORMAT = "Unix"
if (CR > LF) and (CR == len(data)):
  FORMAT = "CP/M"
if (CR < LF) and ((LF+1) == len(data)):
  FORMAT = "Unix (+)"
if (CR > LF) and ((CR+1) == len(data)):
  FORMAT = "CP/M (+)"

for xline in data:
  line=xline.strip()
  line=line.replace(" ","")
  if "coding:" in line:
    (waste,CODING)=line.split("coding:")
  if "#vim:fileencoding=" in line:
    (waste,VIMFF)=line.split("fileencoding=")
  if "VERSION=" in line:
    (waste,XVER)=line.split("VERSION=")

print(  "File Name ................... %s" % (FNAME))
print(  "MD5 ......................... %s" % (str(getDigest("".join(data)))))
print(  "SHA1 ........................ %s" % (str(getDigest("".join(data),"sha1"))))
print(  "Pythong coding marker ....... %s" % (CODING))
print(  "VIM coding marker ........... %s" % (VIMFF))
print(  "VERSION marker .............. %s" % (XVER))
print(  "Chars parsed ................ %i" % (CHARS))
print(  "Lines parsed ................ %i" % (len(data)))
print(  "Found ord(ch) < 10 .......... %i" % (BELOW))
print(  "Found ord(ch) > 128 ......... %i" % (ABOVE))
print(  "Found H-TABs (9) ............ %i" % (TABS9))
print(  "Found CR (13) ............... %i" % (CR))
print(  "Found LF (10) ............... %i" % (LF))
print(  "Found Esc (27) .............. %i" % (ESC))
print(  "Format ...................... %s" % (FORMAT))

if FFLAG:
  print "ASCII check ................. ok. it's ascii"
else:
  print "ASCII check ................. NON-ASCII FILE !!!"


  
