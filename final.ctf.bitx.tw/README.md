## final.ctf.bitx.tw
### Type Juggling: `0e` 
http://final.ctf.bitx.tw:30001/?secret=QNKCDZO

### JSFuck
根據JSFuck的還原
``` plaintext
( -> ] 
) -> !
[ -> )
] -> [
+ -> (
! -> +
```

### Ok, Google
原始碼有一個假flag，該題目可能跟搜尋引擎有關，
`robots.txt`找到`secret.php`

但是`secret.php`依然會判斷user agent
``` bash
curl --user-agent "Googlebot" final.ctf.bitx.tw:10000/secret.php
```
get flag


### Weak Credentials
Show flag 時會送出一個session
並發現該session是md5 hash 的2
將此值改成1 的md5 hash送出並取得flag

### Depreciated Page
https://web.archive.org/web/20200219181820/http://final.ctf.bitx.tw/49a525ebd3494e661e0a16c2dfbee7d1

### Disk Destroyer
png裡面格外的資訊。

### Fortune
推測是執行shell指令因此嘗試
命令注入`$(cat flag.txt)`

### Vigenetale
透過線上詞頻分析解決

### Psychic Py
``` bash
pip2 install --user gmpy2 pycryptodome libnum
```

好像還是缺少什麼WXN，雖然可以反編譯
但不知道怎麼解

### Ez Maht Calculator
nc連上後發現是要求計算的程式，
似乎可以透過python直接計算

似乎都是 
`算式 ======`的格式

可以採用eval，但是該函數並不安全
為了避免被搞，可以用個正則驗證輸入

參見附檔

### Baby_bof
二進制內付shellcode
可能因為系統原因在遠程無法執行，需要稍微修改一下。
payload參見附檔

``` sh
cd home/baby_bof
cat flag
```

### Baby Reverse
``` sh
strings baby_revers
```

### Easy Reverse
將兩組資料dump出來
``` plaintext
                             first
56
59
4f
7a
32
60
34
78
5e
73
32
                             second
0d
48
09
08
48
34
78
7f
4b
03
12
```

- level 1必須符合 `char[i] ^ 1 == first[i]` 
- level 2必須符合 `((char[j] ^ 0x20) - 10) ^ 0x41 == second[j]` 

該算式可以直接反推，不過附檔當初在寫的時候，
誤認為密碼必須符合兩個條件因此暴力解。

### Easy Reverse 2
該題修改原本的python變成keygen
flag的格式為
`WXN{[A-Za-z0-9_!? ()]+}`

根據out.txt，可以發現原文長度為18，
因此猜測 `256 * 18` 為4608是可行的，不過要注意是否重複呼叫隨機數，否則會導致問題。

### Minecraft Symbol
不解釋，反正就腹膜書文字轉成英文

### One Line Python
可以看到output的每行都是hash值，
並且都是由兩個字元組成嘗試產生128^2 = 16384的彩虹表似乎有點大，
不過依然可以先嘗試看看直接生成彩虹表。
``` bash
./one-line-python.py
```

### Ez RSA
透過RSA CTF Tool解決
``` bash
python RsaCtfTool.py -n 40369140384313389211594395887299042283181489800900151210450760841432568667339 \
-e 13337 --uncipher 38701601533462127138915399931209000290344258442601301168697904838260946244394
```

### Mayor
Stegsolve解決即可

### LSB
透過Stegsolve的Stereogram Solver將可疑的bin Planes猜分出來。
因為看到雜訊的圖示，表示可能有隱藏資料。

並且選定LSB與BGR得出文字，內含有flag

### Corrupted PNG
``` bash
pngcheck -vvf corrupted_png.png 
```

pngcheck檢查出IHDR錯誤，透過vim與xxd進行編輯
作法如同
https://github.com/r888800009/CTF-Solve/blob/master/ctf.bitx.tw/README.md#picture-repairer

解完之後發現`libpng warning: IDAT: Too much image data`

而這裡推測原本的CRC是正確的

並且根據這篇的模板進行猜測
https://r888800009.github.io/wiki/ctf-forensics/#ihdr-crc%E4%BF%AE%E5%BE%A9

並且解出高度為300，得到flag

參見附檔

### Dictionary
一開始先分析可以輸入的內容，
雖然不能確定是什麼結構，可能是某種樹狀結構，並且允許節點連向
多個節點。

分析輸入，命令只能打數字之後才能輸入內容，命令為

- `1`: 插入字典樹
- `2`: 查詢字典樹 
- `3`: 輸出

`strings dictionary`發現字串

`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_`
可能是某總枚舉。

猜測輸出為
``` plaintext
樹葉或樹葉
65個節點
```

65個節點分別對映下列Ascii
``` plaintext
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_
00000000000000000000000000000000000000000000000000000000000000000
```

分析資料結構可為Trie tree
驗證概念，透過輸入
``` plaintext
1
ABCD
3
```
與
``` plaintext
1
A
1
B
1
C
1
D
3
```

概念驗證完成，編寫前綴樹讀取程式遍歷。
``` bash
g++ dictionary-search.cpp
./a.out
```

### Rareac
該題一直搞不清楚是什麼密碼，可能是有某種位移。
rail fence與caesar cipher一直無法解碼。

密文`MNDq9W)i*HUbiUD&jU&d_oU(,s`猜測解果是flag
，這樣的話`MND`之間的距離若與`WXN`相同的話，
很有可能是rot加密的變形。

``` python 
ord('M') - ord('N')
ord('W') - ord('X')

ord('X') - ord('N')
ord('N') - ord('D')
```

確認為rot之後，網路上的解密器無法使用，
範圍不正確。

驗證rot的距離，假定要從`M`轉移到`N`與`s`到`}`
要相同。

``` python
ord('W') - ord('M')
ord('}') - ord('s')
```

執行該程式碼之後可以發現距離相同，更可以驗證rot的可行性

編寫python轉位移rot10
``` python
ans = ""
for c in 'MNDq9W)i*HUbiUD&jU&d_oU(,s':
    ans += chr(ord(c) + 10)

print(ans)
```


### Root(Square(P))
由於n過於龐大，透過factordb.com進行分解。
根據提示，n似乎是某種四次方。

得出
`3231660450893985129787028139151018035610437467522069485447060736495328441321407792079915113733222842630322770984020297415912649518117481856420586639729`

安裝環境
``` bash
pip3 install --user gmpy
```

並且透過gmpy進行解決
``` bash
import gmpy
n = 109069392326533749025654872871223983567225261359864234464942960534832300678938964044256497110903289565454100602786599354709092090146291876110976995665947479873542793990727961809934039353965800210757225421293440562162424977500630240175569607027994743285533748794655538144824238805119060830624831035320015563515873361458170472474789880011750152188981718196459654058326837168572338914808105676936901024042927091954247381319618578922826940090273261952857227338536012454202958607396342975333103845139266174275499508380560340652845665074670706485024909474908419209142370029127882095072402593403775370781420481
p = 3231660450893985129787028139151018035610437467522069485447060736495328441321407792079915113733222842630322770984020297415912649518117481856420586639729 
e = 939767 
c = 92252204295903114937298650698346319876545870575090667516745795297099586939047184684100229731286446179861283071892253118508944432604590912246714781232654459516348252806108239506654415842496263826493455017213086337393727723912453492489921720364061529706817631808819186396890937478218135576045397141658879103462787946778247925862447183388917778896209948419326431609592071731628692299710590271596062061708680204690129107467927341656249290998544610615415849438722062314319386932101823521731593701397895927062377588969481311268564590331250001127374247122950376789381557011480575953405549930238852693483682611
d = int(gmpy.invert(e, (p ** 4 - p ** 3 )))
m = pow(c, d, n)

print(bytes.fromhex(format(m, 'x')))
```

解題參考

- [RSA_初體驗 by IKangarooM](https://hackmd.io/@pcyi/SyhP0xYaV?type=view)
- [分解n得到相同的几个p](https://github.com/Zui-Qing-Feng/RSA/blob/master/%E5%88%86%E8%A7%A3n%E5%BE%97%E5%88%B0%E7%9B%B8%E5%90%8C%E7%9A%84%E5%87%A0%E4%B8%AAp)

### 3 Carry System
摩斯密碼，而不是三進位。

- 其中2對映` `
- 1對映`-`
- 0對映`.`

### Nonono
可以用現成的nonogram solver解決該問題。

