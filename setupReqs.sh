#!/bin/bash

#This script will install all required packages and libraries required to run tpmattacker.py

#Installs Dislocker - used for extracting metadata from the encrypted drive
sudo apt install dislocker

#Python3 is required to run tpmattacker.py
sudo apt install python3

#Pip3 is used to get the required python libraries
sudo apt install pip3

#build essential
sudo apt install build-essential

sudo apt install libbde-utils

#python librarires installed
pip3 install pylibftdi

pip3 install sty

pip3 install pycryptodome
