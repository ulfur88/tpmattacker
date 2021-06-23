#!/bin/bash

#This script will install all required packages and libraries required to run tpmattacker.py

#Installs Dislocker - used for extracting metadata from the encrypted drive
sudo apt -y install dislocker

#Pip3 is used to get the required python libraries
sudo apt -y install python3-pip

#build essential
sudo apt -y install build-essential

sudo apt -y install libbde-utils

sudo apt -y install yosys

sudo apt -y install build-essential clang bison flex libreadline-dev gawk tcl-dev libffi-dev git mercurial graphviz xdot pkg-config python python3 libftdi-dev qt5-default python3-dev libboost-all-dev cmake libeigen3-dev

#python librarires installed
pip3 install pylibftdi

pip3 install sty

pip3 install pycryptodome


sudo mkdir /mnt/bitlocker
sudo mkdir /mnt/ntfs
