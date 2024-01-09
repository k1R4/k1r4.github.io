---
layout: post
title: "Text editor v2 [ASIS CTF Finals 2023]"
date: 2024-01-01 14:16:00 +0530
categories: pwn heap
---

## Challenge Description

```
Text editor is back!!

Additional detail: Author's script can exploit remote under 20 seconds ( with 100ms ping to the server )
```

Handout has the challenge binary, libc, ld and Dockerfile

## Initial Analysis

The binary is stripped but it has partial RELRO and PIE disabled which might make exploitation easier :)

Here is the checksec output:
```bash
[k1r4@enderman text-editor-v2]$ pwn checksec chall
[*] '/home/k1r4/work/ctfs/asis-finals-23/text-editor-v2/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'.'
```

This challenge is a unconventional heap note. Here are some key features that set it apart:
- Allows only 2 allocations (limited by global variable)
- Allocation size can't be controlled
- Allocation size is always greater than the previous allocation size
- Can't free without allocating another chunk

## Breakdown of the challenge

The challenge is based on the idea of a text editor. Each chunk can be thought of as an open file in the editor. Each chunk is referred to as a tab. There can be a maximum of 2 tabs at a time. This limit is enforced through a variable in the .bss section. Also if a tab is completely filled with characters, its allocation size is doubled, and the original tab is freed. This is the structure of a tab:
```c
struct tab_t
{
  unsigned long curr_size;
  unsigned long max_size;
  char *buffer;
}
```
The binary exposes 4 options to the user:
 - Type characters  (append characters to a tab)
 - Backspace  (remove trailing characters in a tab)
 - Open new tab (create new tab and add content)
 - Select tab (select the tab to operate on)

The implementation for opening new tabs and selecting tab are straightforward. On the other hand, typing characters and backspace seem convoluted. Here is my interpretation of the pseudocode, which is hopefully easier to follow:
```c
void type_characters(void)
{
  char buf[2056];

  printf("Type characters: ");
  int red = read(0, buf, 2047);

  for(int i = 0; i < red; i++)
    add_char(tabs[curr_tab], buf[i]);

  print_tab();
  puts("Done!");
}

void add_char(tab_t *tab, char c)
{
  if(tab->curr_size == tab->max_size)
  {
    char *buf = malloc(tab->max_size*2);
    memcpy(buf, tab->buffer, tab->max_size);
    free(tab->buffer);
    tab->buffer = buf;
    tab->max_size *= 2;
  }
  tab->buffer[tab->curr_size++] = c;
  tab->buffer[tab->curr_size] = 0;
}

```
- The first tab is initialized with size 0x18
- If a tab has reached capacity, its buffer is freed and doubled in capacity
- The buffer always ends with a null byte

```c
void backspace(void)
{
  int count = -1;
  printf("How many times? ");
  scanf("%d", &count);

  for(int i = 0; i < count; i++)
    backspace_tab(tabs[curr_tab]);
  printf_tab();
  puts("Done!")
}

void backspace_tab(tab_t *tab)
{
  if(tab->curr_size)
  {
    tab->buffer[tab->curr_size--] = 0;
  }
}
```
- Backspace replaces the trailing character of the buffer with a null byte
- It also decrements curr_size

## Bug
The bug is present in `add_char()`:
```c
tab->buffer[tab->curr_size++] = c;
tab->buffer[tab->curr_size] = 0;
```
When `tab->curr_size + 1 = tab->max_size`, the last character of the buffer is added, it will cause a null byte overflow. But this is only true if the buffer is allocated with a size ending in 0x8. Otherwise malloc allocates a larger chunk and it won't be possible to reach the end of the chunk, since `tab->max_size < size of buffer`

This can be abused to unset `prev_inuse` bit of a following chunk.

## Exploit Stratergy

Here is the .bss layout for the binary which might make the exploit easier to understand:
```c
// .bss memory Layout
0x4040e0: tab[0].curr_size
0x4040e8: tab[0].max_size
0x4040f0: tab[0].buffer
0x4040f8: tab[1].curr_size
0x404100: tab[1].max_size
0x404108: tab[1].buffer
0x404110: curr_index << 32 | max_tabs 
```

- Append 0x600 chars to first tab with initial size of 0x18
	- It keeps doubling in size until it can accommodate, leaving behind a trail of chunks in tcache
	- It ends up allocating a chunk of size 0x610 (`malloc(0x600)`)
	- The previous chunk is of size 0x310 (`malloc(0x300)`)
	- Add a fake chunksize at the end of 0x610 chunk to pass nextchunk checks later on
	
- Create a new tab with size of 0x308 to claim the 0x310 chunk present before the 0x610 chunk
	- Forge a fakechunk of size 0x300 in the body of the 0x310 chunk
	- Setup fd and bk pointers to bypass unlink checks, using pointer present in .bss
	- Set prevsize(0x610) as 0x300
	- Append null bytes till `curr_size = max_size`, this causes null byte overflow and changes size of 0x610 to 0x600 (with prev_inuse bit unset)

- Freeing the 0x610 (now 0x600) chunk will now cause coalescing with fake 0x300 chunk
- Append chars to first tab again to cause it to be freed
- Unlink causes `tab[1].buffer` to be replaced with pointer to bss
- Use tab with bss pointer to increase `max_tabs`
- Create fake tabs to point to GOT table
- Profit! 


## Conclusion

I haven't seen a unique heap challenge in a while, this was a lot of fun to solve. I ended up getting the blood on this one :) 

You can find the full exploit [here](https://gist.github.com/k1R4/e6a789ce2919c81d965a6008eb153a06)

Flag: `ASIS{43e4d80210d69cb008e30defc252a9de}`