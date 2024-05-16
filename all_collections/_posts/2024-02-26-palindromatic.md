---
layout: post
title:  "palindromatic [bi0sCTF24]"
date:   2024-02-26 18:58:23 +0530
categories: pwn kernel
---

## Challenge Description

`An unnecessarily complex palindrome checker, implemented as a kernel driver. What could possibly go wrong?`

Handout has the files bzImage, rootfs.ext3, run.sh, the module (.ko) and its source code. A sample .config is also included to indicate what security features are compiled in.

## Initial Analysis

### Mitigations

SMEP, SMAP, KPTI and KASLR are all enabled as seen in `run.sh`. Additionally typical slub hardening features are enabled and `modprobe_path` overwrite isn't possible due to `CONFIG_STATIC_USERMODEHELPER`.
Although `CONFIG_RANDOM_KMALLOC_CACHES` makes exploitation harder by reducing chances of similarly sized objects being in the same cache, it doesn't prevent cross-cache attacks.

### The Module

The module is a glorified and overcomplicated palindrome checker. Users can submit requests and operate on submitted requests through ioctl. There are two queues to keep track of requests, `incoming_queue` and `outgoing_queue`. The functionalites offered by the ioctl are:
 + For incoming queue,
    - QUEUE => add request to rear of incoming_queue
    - SANITIZE => update request at front by translating \[A-Z\|a-z\] to \[A-Z\] & discarding other chars
    - RESET => pop request at front, if sanitized, reset to raw and send it to rear, otherwise discard
    - PROCESS => pop request at front, check if palindrome and add to rear of outgoing_queue
 + For outgoing queue,
    - REAP => pop request at front, provide verdict if it was a palindrome or not
 + QUERY => returns available capacity in both queues

### More on requests
```c
typedef struct request_t 
{
    ptype type;
    unsigned long magic;
    char str[STRING_SZ];
    char sanstr[STRING_SZ];
} request_t;
```
- `ptype` indicates whether the request is unprocessed [RAW, SANITIZED] or processed [PALINDROME, NONPALINDROME] 
- `magic` is used to check for corrupted requests (not really :P)
- `str` is the buffer where the string for a request is stored
- `sanstr` is the buffer where the sanitized string for a request is stored

Requests are allocated in a separate cache due to `SLAB_NO_MERGE`. Since there are no pointers or critical members in request, to leverage any bug in the driver, we will have to perform a cross-cache attack.
```c
pm_cache = kmem_cache_create("palindromatic", TARGET_SZ, __alignof__(request_t), 
                            SLAB_ACCOUNT | SLAB_PANIC | SLAB_HWCACHE_ALIGN | SLAB_NO_MERGE, NULL);
```

## Bugs

The main bug is null byte overflow, that occurs in `pm_sanitize_request()` if the `str` buffer is completely filled with characters in [A-Z].
```c
for(int i = 0; i < STRING_SZ; i++)
{
    if(!req->str[i]) break;

    if(req->str[i] > 0x60 && req->str[i] < 0x7b)
        temp_buffer[ptr++] = req->str[i]-0x20;

    else if(req->str[i] > 0x40 && req->str[i] < 0x5b)
        temp_buffer[ptr++] = req->str[i];

    else continue;
}

temp_buffer[ptr] = 0;
strcpy(req->sanstr, temp_buffer);
```
If the null byte overflow occurs, the `ptype` of request below (in memory) will be corrupted. This by itself is a fairly harmless bug. But now taking a look at `pm_process_request()`

```c
request_t *req = pm_queue_peek(&incoming_queue);
.
.
idx = pm_queue_enqueue(&outgoing_queue, req);
if(idx < 0) goto end;

memset(temp_buffer, 0x0, STRING_SZ);
if(req->type == RAW)
{
    .
    .
    pm_queue_dequeue(&incoming_queue);
}

if(req->type == SANITIZED)
{
    .
    .
    pm_queue_dequeue(&incoming_queue);
} 

return idx;
```
Majority of the code in processing doesn't concern the exploitation, so it can be ignored. Initially the request at front of `incoming_queue` is added to rear of `outgoing_queue`. The request is only removed from the `incoming_queue` at the end of the if clauses. However when processing request with corrupted `ptype`, it won't enter either if clause, so it will never get removed from `incoming_queue`. This can lead to UAF if the request is reaped from `outgoing_queue` but it still remains in `incoming_queue`.
Resetting a request in `incoming_queue` will eventually free it, giving a potential free primitive on UAF request.

## Exploit Strategy

### Triggering UAF (Stage 1)
- Spray requests, filling the `incoming_queue`
- Triggering `SANITIZE` now has a high chance of corrupting another request
- Now `PROCESS` one request at a time and `QUERY` capacity
- If capacity of `incoming_queue` doesn't change, it means a corrupted request was processed
- `RESET` to send the corrupted request back to rear of `incoming_queue`
- `PROCESS` remaining requests and `REAP` them all
- Now corrupted request is left in `incoming_queue` while it has already been freed by reaping.

### Convert UAF request to pipe_buffer (Stage 2)
For the remainder of the exploit, I used `pipe_buffer` and `msg_msgseg`. The reason being, I came across this [cool technique](https://github.com/veritas501/pipe-primitive), which is essentially modifying `flags` of a `pipe_buffer` to `PIPE_BUF_FLAG_CAN_MERGE`. If the pipe was spliced from a readonly file, writing to the pipe after this will actually write to the file. In short, another primitive can potentially be abused to revive the infamous DirtyPipe. `msg_msgseg` is used to overlap on the `pipe_buffer` to leak and modify it.

- Since all requests have been freed, the slab with UAF request is also returned to allocator
- Spray a lot of `pipe_buffer` using `pipe()`
- This will eventually re-allocate the slab with UAF request (cross-cache)
- This is quite reliable since `pipe_buffer` and requests are similarly sized and have slabs of same order
- Write some content to the pipes
- Trigger free of victim `pipe_buffer`, through resetting UAF request twice
- `RESET` once to set `ptype` as `RAW` and once more to actually free it
- Spray some more `pipe_buffer` to occupy slot of victim 
- Write different content to the pipes in the second spray
- Check content of all pipes from first spray to find victim pipe

### Overwrite pipe_buffer flags (Stage 3)
A quick look at `pipe_buffer`:
```c
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};
```
The actual `pipe_buffer` object that is allocated is actually a ring of `pipe_buffer` structs. Initially the object is empty, when its written to for the first time, a `pipe_buffer` is added to the ring. This can also be triggered by `F_SETPIPESZ` function of `fcntl()`. Additionally, splicing also adds a new `pipe_buffer` to the ring. Armed with this information, the exploit might make more sense.

- Now free all `pipe_buffer` by `close()`, while holding a reference to the victim `pipe_buffer`
- Spray `msg_msgseg` using `msgsnd()`
- `msg_msgseg` is used in instead of `msg_msg` since it has a smaller header
- Doesn't cause issues when overlapped with `pipe_buffer`
- `msg_msgseg` of size 0x400 is used since its the same size as `pipe_buffer` object
- `msg_msgseg` now completely overwrites the `pipe_buffer` object
- Splice from `/etc/passwd` to the victim pipe, this will add a new `pipe_buffer` struct to the ring
- Using `msgrcv()` the `pipe_buffer` can be leaked
- Use leak to craft fake `pipe_buffer` with `flags = PIPE_BUF_FLAG_CAN_MERGE`
- Spray `msg_msgseg` again, this time containing fake `pipe_buffer`
- Writing to victim `pipe_buffer` will now, write to `/etc/passwd`

This is because of the logic in `pipe_write()` which writes into the backing page of the lastly added `pipe_buffer` in the ring, if `PIPE_BUF_FLAG_CAN_MERGE` is set. Finally use `su` to login as root :D

## Conclusion

I learnt a lot about crosscache when working on this challenge. Hope you learnt something too!

You can find the full exploit [here](https://gist.github.com/k1R4/bf302fffc2bd5e313a0f7ad789fbd363)

Flag: `bi0sctf{p4l1ndr0me5_4r3_pr0bl3m4t1c_frfr_b851ea94}`