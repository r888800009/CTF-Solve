# hackme.inndy.tw Solve
## 2
  ``` bash
    stegsolve corgi-can-fly.png
  ```

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

## 21 SQL Injection
  user: `admin`, password:``\' or `user`= "admin" #``

## 31
  create cookie `show_hidden`:`yes`

## 41 helloworld
  ```
    objdump -d helloworld | less
  ```
  then find `main` label, then find `cmp` instruction

## 57 catflag
  connect to server then type
  ``` bash
    cat flag
  ```

## 81 easy
  hex and base64

## 82 r u kidding
  using Caesar Cipher decoder, `a->z`

