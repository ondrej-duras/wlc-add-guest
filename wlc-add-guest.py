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


####################################################################### }}} 1
## CONFIG handling #################################################### {{{ 1

####################################################################### }}} 1
## AUTHORIZATION ###################################################### {{{ 1

####################################################################### }}} 1
## GUEST handling ##################################################### {{{ 1

####################################################################### }}} 1
## MAIN ############################################################### {{{ 1

####################################################################### }}} 1
# --- end ---

