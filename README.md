# NOPe
A quick hacky script to test some NOP sled alternatives

> Note: You'll need to use the correct architecture python install for each script

Usage:
```
python Nope_x64.py #Runs MSFVenom Messagebox
python Nope_x64.py file.bin #Runs user supplied bin
```


Shellcode regen steps:
```
msfvenom -p windows/x64/messagebox > msgbox.x64.bin
msfvenom -p windows/messagebox > msgbox.x86.bin
```