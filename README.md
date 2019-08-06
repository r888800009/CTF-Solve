# CTF-Solve
  - [radare2](https://github.com/radare/radare2) reverse engineering framework

## pwn
  ``` bash
  # check file type (ex: 32bit, 64bit
  file binary

  # check sec 
  checksec --file=a.out 

  ```

### ROP tools
  - [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) find gadget
  - [Ropper](https://github.com/sashs/Ropper) find gadget and semantic
  - [ROPGenerator](https://github.com/Boyan-MILANOV/ropgenerator) semantic
  
  ``` bash
  # install ropper
  pacman -S ropper
  pacaur -S python-z3 python-pyvex-git  python-archinfo-git # if need semantic
  ```

#### Q&A
  - `ropper` `semantic` not found gadgets using `--clear-cache`

### pwntools
  debug
  ``` python
  # show log
  context.log_level ='debug'

  # gdb
  context.terminal = ['alacritty', '-e', 'sh', '-c']
  gdb.attach(c)
  ```

### GOT
  - find plt/got `objdump -R binfile`

### Reference
  - [linux常见漏洞利用技术实践](https://wooyun.js.org/drops/linux%E5%B8%B8%E8%A7%81%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E6%8A%80%E6%9C%AF%E5%AE%9E%E8%B7%B5.html)
  - [pwntools的一些简单入门总结](https://prowes5.github.io/2018/08/06/pwntools%E7%9A%84%E4%B8%80%E4%BA%9B%E7%AE%80%E5%8D%95%E5%85%A5%E9%97%A8%E6%80%BB%E7%BB%93/)
  - [Exploit利器——Pwntools](http://brieflyx.me/2015/python-module/pwntools-intro/)
  - [Binary exploitatio](https://www.slideshare.net/AngelBoy1/binary-exploitation-ais3)

## web
  - SSRF

### sqlmap
  ```
  sqlmap -u "https://hackme.inndy.tw/gb/?mod=post" --method POST -p "content,title" --data "title=a&content=b"  
  sqlmap -u "https://hackme.inndy.tw/gb/?mod=post" --method POST -p "content,title" --data "title=a&content=b" --level=3 --risk=3 # if above not working
  ```

### XSStrike
  - [XSStrike](https://github.com/s0md3v/XSStrike)
  
## other
  hashcat insall
  ``` bash
  sudo pacman -S hashcat, opencl-mesa # or opencl-nvidia
  ```
