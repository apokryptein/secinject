## Section Mapping Process Injection (secinject): Cobalt Strike BOF

Beacon Object File (BOF) that leverages Native APIs to achieve process injection through memory section mapping. It implements two commands via an Aggressor Script: one to inject beacon shellcode for a selected listener into the desired process, and one to inject the user's desired shellcode - loaded from a bin file - into the desired process.  These are *sec-inject* and *sec-shinject* respectively.

- Currently, this is only implemented for x64 processes.

### How to Make
```
git clone https://github.com/apokryptein/secinject.git
cd secinject/src
make
```

### How to Use
#### Injecting Beacon
```
sec-inject PID LISTENER-NAME
```

#### Injecting Other Shellcode
```
sec-shinject PID /path/to/bin
```

### Code References
https://github.com/EspressoCake/Process_Protection_Level_BOF/

https://github.com/rsmudge/CVE-2020-0796-BOF/blob/master/src/libc.c

https://github.com/connormcgarr/cThreadHijack/

https://github.com/boku7/HOLLOW/

https://github.com/ajpc500/BOFs/




