#!/bin/zsh
gcc ./hackme.inndy.tw.fast.c

echo start
coproc nc hackme.inndy.tw 7707

# drop line
read <&p
read <&p
read <&p

#
echo "Yes I know">&p
stdbuf -o 0 cat <&p|tee log.txt|stdbuf -o 0 awk '{print $1,$2,$3}' |./a.out|tee log2.txt >&p


