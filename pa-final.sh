#!/bin/bash
echo
echo "Script to run The Final Programming Assignment"
echo "By: Joshua Boyles"

rm -f dispatcher amal/amal amal/logAmal.txt basim/basim basim/logBasim.txt basim/bunny.txt kdc/kdc kdc/logKDC.txt

echo "=============================="
echo "Compiling all source"
    gcc amal/amal.c   myCrypto.c -o amal/amal    -lcrypto
    gcc basim/basim.c myCrypto.c -o basim/basim  -lcrypto
    gcc kdc/kdc.c     myCrypto.c -o kdc/kdc      -lcrypto
    gcc genKey.c                 -o genKey       -lcrypto
    gcc wrappers.c dispatcher.c  -o dispatcher

echo "=============================="
echo "Generating and distributing master keys"
./genKey

# Send master key to Amal
cd amal
rm -f key_amal.bin iv_amal.bin
ln -s ../key_amal.bin key_amal.bin
ln -s ../iv_amal.bin  iv_amal.bin

# Send master key to Basim
cd ../basim
rm -f key_basim.bin iv_basim.bin
ln -s ../key_basim.bin key_basim.bin
ln -s ../iv_basim.bin  iv_basim.bin

# Send all master keys to the KDC
cd ../kdc
rm -f key_amal.bin iv_amal.bin key_basim.bin iv_basim.bin
ln -s ../key_amal.bin key_amal.bin
ln -s ../iv_amal.bin  iv_amal.bin
ln -s ../key_basim.bin key_basim.bin
ln -s ../iv_basim.bin  iv_basim.bin

cd ..

echo "=============================="
echo "Starting the dispatcher"
./dispatcher

echo
echo
echo "======  Amal's  LOG  ========="
cat amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat basim/logBasim.txt

echo
echo "=====  The KDC's  LOG  ========"
cat kdc/logKDC.txt
echo
echo

diff -s amal/bunny.mp4 basim/bunny.mp4
echo
echo
