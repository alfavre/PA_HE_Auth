#!/bin/bash

SLEEP_TIME=1
LEFT=$1
RIGHT=$2
#init
echo "init"
./age_verification_init
echo "init done"
sleep $SLEEP_TIME

#encrypt $LEFT
echo "encrypt $LEFT"
./age_verification_encrypt $LEFT
echo "encrypt $LEFT done"
sleep $SLEEP_TIME

echo "move to $LEFT"
mv ct_av.bin ct_av_$LEFT.bin
echo "mv $LEFT done"
sleep $SLEEP_TIME

#encrypt $RIGHT
echo "encrypt $RIGHT"
./age_verification_encrypt $RIGHT
echo "encrypt $RIGHT done"
sleep $SLEEP_TIME

echo "move to $RIGHT"
mv ct_av.bin ct_av_$RIGHT.bin
echo "mv $RIGHT done"
sleep $SLEEP_TIME

#decrypt $LEFT
echo "decrypt $LEFT"
./age_verification_decrypt privkey_av.bin ct_av_$LEFT.bin
echo "decrypt $LEFT done"
sleep $SLEEP_TIME

#decrypt $RIGHT
echo "decrypt $RIGHT"
./age_verification_decrypt privkey_av.bin ct_av_$RIGHT.bin
echo "decrypt $RIGHT done"
sleep $SLEEP_TIME

#main
echo "main"
./age_verification_main ct_av_$LEFT.bin ct_av_$RIGHT.bin
echo "main done"
sleep $SLEEP_TIME

#decrypt op
echo "decrypt op"
./age_verification_decrypt privkey_av.bin ct_av_result.bin
echo "decrypt op done"
sleep $SLEEP_TIME

echo clean
rm ./*.bin
echo cleaned
