[Back](PicoFrontPage.md)

# some challenges from crackmes.one

---

## 4N0NY31TY's First Crackme


- Author: 4N0NY31TY
- Difficulty: 1.4/5
- Platform: Unix/Linux etc.

### Tools

* Pwntools - Python
* Disassembler - Cutter

### Analysis

If I piece everything together, I can assume that the source code would look something like this:

```c
char* input() {
    allocate memory
    read characters and add to var_19h
    reallocate memory if greater than size
    once new line is read, exit and return ptr
}

int len(char* arg1) {
    loop through arg1 and calculate length
    return length
}

int main() {
    arg1 = input;

    for (int var_ch = 0; var_ch < len(arg1); var_ch++) {
        var_10h = var_10h + arg1[var_ch];
    }

    if (var_10h == len(arg1)*-10 + 0x34e7) {
        printf("License is valid!\n");
    } else {
        printf("License is invalid!\n");
    }
}
```

We need to do the math for this. Find a value that is equal to its `length*-10 + 0x34e7 (13543)`.

If we look at an ASCII table, we can see that the character *z* has a high decimal value of 122.

Through trial and error, I calculated that a value of 102 *z*'s would land very close to `102*-10 + 13543 = 12523`.
From there if we add one more character we could find a value that would be able to complete the input.
I was able to calculate this as the ASCII character *E* and outcome with a final value of ***12513***.

I thought that actually typing in 103 characters would be infeasible, so I used Pwntools.

### Solution

```python
from pwn import *

context.arch = "amd64"
c = constants

PROGNAME = "./crackme"
REMOTE = ""
REMOTEPORT = 0

if args.REMOTE:
    p = remote(REMOTE, REMOTEPORT)
else:
    pty = process.PTY
    p = process(PROGNAME, stdin=pty, stdout=pty)

elf = ELF(PROGNAME)
#libc = ELF("") #elf.libc

# payload
payload = b'z'*102 + b'E'
# len = -10*103 + 0x34e7 = 12513
# var_10h = 122*102 + 1*69 = 12513

p.recvuntil(b'Enter License: ')

p.sendline(payload)

recvmsg = p.recvall()
print(recvmsg)

p.interactive()
```

---

## PleaseCrackMe

- Author: RaphDev
- Difficulty: 1.4/5
- Platform: Unix/Linux etc.

### Tools

* Pwntools - Python
* Disassembler - Cutter

### Analysis

```c
int number;
char[] username;
char[] password;

printf("\nType username: ");
scanf("%s", &username);

printf("\nType number between 1 and 9: ");
scanf("%i", %number);

if (number < 1) {
   printf("Error: Too small");
   exit(-1);
} else if (number < 10) {
   int i;
   for (i = 0; i < strlen(username); i++) {
      char[] s1;
      char ascii_number = number;
      s1[number] = ascii_number + username[number];
   }

   printf("\nEnter a password: ");
   scanf("%s", &password);

   int success;
   success = strcmp(&password, &s1);

   if (success == 0) {
      printf("Success\n");
   } else {
      printf("Unsuccessful\n");
   }
} else {
   printf("Error: Too large");
   exit(-1);
}

exit(0);
```

Basically, this is just the Caesar Cipher. Very easy to crack.

Shift each letter of the `username` by `user_number` positions in the alphabet to get the `user_password`.

For e.g., we have `username` of `wer` with a key (`user_number`) of `5`.

```
abcdefghijklmnopqrstuvwxyz

fghijklmnopqrstuvwxyz{|}~[DEL]
```

Easy-to-read ASCII conversion charts can be found online.

The `user_password` will then be: `|jw`.

Thus, is the Caesar Cipher.


### Solution

```python
from pwn import *

context.arch = "amd64"
c = constants

PROGNAME = "./PleaseCrackMe"
REMOTE = ""
REMOTEPORT = 0

if args.REMOTE:
    p = remote(REMOTE, REMOTEPORT)
else:
    pty = process.PTY
    p = process(PROGNAME, stdin=pty, stdout=pty)

elf = ELF(PROGNAME)
#libc = ELF("") #elf.libc

# variables
username = b'ABCD'
user_number = b'3'
user_password = b'DEFG'

# password
p.recvuntil(b'Type in your Username: ')
p.sendline(username)

p.recvuntil(b'Type in a number between 1 and 9: ')
p.sendline(user_number)

p.recvuntil(b'Type in the password: ')
p.sendline(user_password)

recvmsg = p.recvall()
print(recvmsg)

p.interactive()
```
