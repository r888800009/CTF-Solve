# 2019game.picoctf.com/game

## General skills

### Based
``` python
import codecs
print(''.join([chr(int(c , 2)) for c in input().split()]))
print(''.join([chr(int(c , 8)) for c in input().split()]))
print(codecs.decode(input(), "hex"))
```
### strings
``` bash 
strings strings | grep pico  
```

## VaultDoor1
step0: Get code
``` plaintext
        return password.length() == 32 &&
               password.charAt(0)  == 'd' &&
               password.charAt(29) == '8' &&
               password.charAt(4)  == 'r' &&
               password.charAt(2)  == '5' &&
               password.charAt(23) == 'r' &&
               password.charAt(3)  == 'c' &&
               password.charAt(17) == '4' &&
               password.charAt(1)  == '3' &&
               password.charAt(7)  == 'b' &&
               password.charAt(10) == '_' &&
               password.charAt(5)  == '4' &&
               password.charAt(9)  == '3' &&
               password.charAt(11) == 't' &&
               password.charAt(15) == 'c' &&
               password.charAt(8)  == 'l' &&
               password.charAt(12) == 'H' &&
               password.charAt(20) == 'c' &&
               password.charAt(14) == '_' &&
               password.charAt(6)  == 'm' &&
               password.charAt(24) == '5' &&
               password.charAt(18) == 'r' &&
               password.charAt(13) == '3' &&
               password.charAt(19) == '4' &&
               password.charAt(21) == 'T' &&
               password.charAt(16) == 'H' &&
               password.charAt(27) == '3' &&
               password.charAt(30) == '4' &&
               password.charAt(25) == '_' &&
               password.charAt(22) == '3' &&
               password.charAt(28) == 'f' &&
               password.charAt(26) == '0' &&
               password.charAt(31) == '1';
```

step1
``` plaintext
:%s/.charAt(/[/g
:%s/)/]/g
:%s/==/=/g
:%s/;//g
:%s/&&//g
:%s/ //g
```

step2
``` python
password = [0] * 32
password[0]='d'
password[29]='8'
password[4]='r'
password[2]='5'
password[23]='r'
password[3]='c'
password[17]='4'
password[1]='3'
password[7]='b'
password[10]='_'
password[5]='4'
password[9]='3'
password[11]='t'
password[15]='c'
password[8]='l'
password[12]='H'
password[20]='c'
password[14]='_'
password[6]='m'
password[24]='5'
password[18]='r'
password[13]='3'
password[19]='4'
password[21]='T'
password[16]='H'
password[27]='3'
password[30]='4'
password[25]='_'
password[22]='3'
password[28]='f'
password[26]='0'
password[31]='1'
print(''.join(password))
```

## VaultDoor3.java

``` python
buffer = "jU5t_a_sna_3lpm17ga45_u_4_mbrf4c"
password = [0] * 32

# for (i=0; i<8; i++) buffer[i] = password.charAt(i);
for i in range(0, 8):
    password[i] = buffer[i]

# for (; i<16; i++) buffer[i] = password.charAt(23-i);
for i in range(8, 16):
    password[23 - i] = buffer[i]

# for (; i<32; i+=2) buffer[i] = password.charAt(46-i);
for i in range(16, 32, 2):
    password[46 - i] = buffer[i]

# for (i=31; i>=17; i-=2) buffer[i] = password.charAt(i);
for i in range(31, 17 - 1, -2):
    password[i] = buffer[i]

print(''.join(password))
```

## VaultDoor4.java
``` java
import java.io.UnsupportedEncodingException;
import java.util.*;

class VaultDoor4 {
  public static void main(String args[]) {
    byte[] myBytes = {
        106,
        85,
        53,
        116,
        95,
        52,
        95,
        98,
        0x55,
        0x6e,
        0x43,
        0x68,
        0x5f,
        0x30,
        0x66,
        0x5f,
        0142,
        0131,
        0164,
        063,
        0163,
        0137,
        0142,
        071,
        'e',
        '9',
        '2',
        'f',
        '7',
        '6',
        'a',
        'c',
    };

    try {
      String s = new String(myBytes, "UTF-8");
      System.out.println(s);
    } catch (UnsupportedEncodingException e) {
    }
  }
}
```

print flag
``` bash
javac VaultDoor4.java
java VaultDoor4
```

## 水題 
- Insp3ct0r: 三個部份瀏覽後接在一起
- where are the robots
  - https://2019shell1.picoctf.com/problem/4159/robots.txt
  - https://2019shell1.picoctf.com/problem/4159/a44f7.html
- The Numbers 
  - ''.join([chr(ord('A') - 1 + c)for c in [16, 9, 3, 15, 3, 20, 6, 20, 8, 5, 14, 21, 13, 2, 5, 18, 19, 13, 1, 19, 15, 14]])
- 13: rot

## web
### logon
``` bash
curl https://2019shell1.picoctf.com/problem/32270/flag --cookie 'admin=True' 
```
### Open-to-admins
``` bash
curl https://2019shell1.picoctf.com/problem/49858/flag --cookie 'admin=True;time=1400' 
```
### Irish-Name-Repo 1

SQL injection

https://2019shell1.picoctf.com/problem/12273/login.html

user name
``` SQL
' or 1 = 1 --
```

### Empire1
Create a Card 的 `/`、`-`、`/` 被過濾
