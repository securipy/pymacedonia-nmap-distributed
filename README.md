# pymacedonia-nmap-distributed
NMAP Distributed plugin for Macedonia

### How to install

Clone it and install the requirements (think about to use virtual-envs, as you will ^^)
```
$ git clone https://github.com/securipy/pymacedonia-nmap-distributed.git .

$ pip install -r requirements.txt
```

### How to use it

#### Cron

```
*/5 * * * * $PATH_TO_REPO/nmap_distributed.py
```

#### Manual execution (testing)

```
$ python $PATH_TO_REPO/nmap_distributed.py 
```

