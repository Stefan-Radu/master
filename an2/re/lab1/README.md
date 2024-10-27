# Task 1 linux

## lib function called

* memset
* fgets
* strlen
* puts
* exit

## length: 70

see `./cracklen.sh`

## other checks

Just keep inspecting ltrace. There are a number of check which
look for certain substrings in the password. We can gather this 
way a set of cribs, which permuted make the password.

```python
cribs = [b'zihldazjcn', b'vlrgmhasbw', b'jqvanafylz', b'hhqtjylumf', \
         b'yemlopqosj', b'mdcdyamgec', b'nhnewfhetk']
```


## to get the full password just try all permutations

see `./exploit.py` and the following listing

```sh
$ grep -anE "^[a-z0-9{}]+$" ./flags.txt
1406:w
1503:5
2322:u
3496:2
4176:5
5670:timctf{7dfadd1ee67a9c516c9efbf8f0cf43f4}

$ echo "nhnewfhetkmdcdyamgeczihldazjcnhhqtjylumfvlrgmhasbwjqvanafylzyemlopqosj" | ./crackme
Congrats. If that is the correct input you will now get a flag
If all you see is garbage, try a different one
timctf{7dfadd1ee67a9c516c9efbf8f0cf43f4}
```

# Task 2 Windows

1. From API monitor: the malware attempts a GET request to http://maybe.suspicious.to/secondstage
2. From ProcMon:
    - HKLM (HKEY_LOCAL_MACHINE)
    - HKCU (HKEY_CURRENT_USER)
    - HKU  (HKEY_USERS)
