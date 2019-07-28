# CTF-Solve
## pwn
  ``` bash
  # check file type (ex: 32bit, 64bit
  file binary

  # check sec 
  checksec --file=a.out 

  ```

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

## web
  - SSRF
