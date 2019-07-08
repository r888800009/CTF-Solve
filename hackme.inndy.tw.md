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
  
## 18 homepage
  `f12`->`console`

## 19 ping (os command injectio)
  `$(tail *)`

## 21 SQL Injection
  user: `admin`, password:``\' or `user`= "admin" #``

## 31
  create cookie `show_hidden`:`yes`

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

