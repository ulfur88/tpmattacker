!/bin/bash

git clone https://github.com/YosysHQ/nextpnr
git clone https://github.com/YosysHQ/icestorm

cd icestorm
make -j$(nproc)
sudo make install
cd ..

cd nextpnr
cmake . -DARCH=ice40
make -j$(nproc)
sudo make install
cd ..
