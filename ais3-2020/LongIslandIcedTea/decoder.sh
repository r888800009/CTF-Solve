#!/bin/bash
# echo {_,\!,{A..Z},{a..z},{0..9}}{_,\!,{A..Z},{a..z},{0..9}}{_,\!,{A..Z},{a..z},{0..9}} > wordlist
echo > genlist
for str in $(cat wordlist)
do
  echo "AIS3{$str"irl_g1v3_m3_Ur_IG_4nd_th1s_1s_m1ne_terryterry__\} >> genlist
  echo "AIS3{$str"irl_g1v3_m3_Ur_IG_4nd_th1s_1s_m1ne_terryterry__\}| ./Long_Island_Iced_Tea >> genlist
  echo \n\n  >> genlist
done
