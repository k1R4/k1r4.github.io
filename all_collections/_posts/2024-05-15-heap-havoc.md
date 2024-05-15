---
layout: post
title:  "Heap Havoc [LinuxKernel]"
date:   2024-05-15 21:16:00 +0530
categories: pwn kernel
---

## Introduction

The kernel heap is a lot more complicated and chaotic than userspace heap. Let's break it down one step at a time. Here are some things to keep in mind before going forward:
- `kmalloc` and `kfree` are used to allocate and free memory respectively. they are the most commonly used heap API functions in the kernel codebase 
- When memory is requested through `kmalloc`, it is taken from a `slab`, which  in turn consists of `pages`
- `pages` are continous memory units aligned by `0x1000`, on x86 atleast
- `pages` are contiguous in virtual memory but need not be physically contiguous
- `slabs` are of various orders starting from 0. A `slab` of order 0, consists of 2<sup>0</sup> = 1 `page`, a slab of order 1, consists of 2<sup>1</sup> = 2 `pages`.
- There are separate allocators for `pages` and `slabs`
- There is only one page allocator in the kernel, known as the `Binary Buddy Allocator`. It exposes certain page allocation API such as `alloc_pages`, `__free_pages`
- There are 3 `slab` allocators: `SLOB`, `SLAB` and `SLUB`. They use the page allocator for obtaining slabs. They expose `kmalloc` and `kfree` APIs

Let's now look at each of these allocators one by one and how it all adds up. At the end of each section, there will be some links for more info on the same. They are references I used or came across while learning about the kernel heap.


## SLOB

Stands for Simple List of Blocks. This slab allocator is typically used in embedded systems or machines where memory is very limited. This allocator has been deprecated since v6.2. Some features of SLOB are:
- Implemented through less code since its simpler that other allocators
- It is memory efficient, however doesn't scale and suffers from fragmentation
- Stores the freelist in the object itself
- Has multiple freelists based on size namely: small, medium and large
- If no memory is available in the freelist, extends heap using page allocator
- Uses K&R style allocation (Section 8.7, The C Programming Language)

[LWN Article on SLOB](https://lwn.net/Articles/157944/)
[Paper on SLOB exploitation](https://research.nccgroup.com/wp-content/uploads/2020/09/VSR-slob-exploitation.pdf)

Before delving into SLAB and SLUB allocators, we have to first understand `kmalloc-caches`


## kmalloc-caches

`kmalloc-caches` are "isolated" groups of slabs that are used to allocate memory of a particular size or for allocating specific objects. I put isolated in quotes since it is not always true. More about that in the upcoming sections.  Caches are often initialized with some empty slabs to speed up allocations. By default there are a lot of caches that are created for objects of various sizes and types. Some of them being:
- kmalloc-32
- kmalloc-192
- kmalloc-1k
- kmalloc-4k
- files_cache
- inode_cache

The caches starting with "kmalloc" are called as general purpose caches. By default an allocation will end up in one of those caches depending on size requested. For example a request of size 32,
ends up in `kmalloc-32`, anything above that will be allocated in `kmalloc-64` which is the next cache. There are certain caches that are reserved for objects of a specific type, such as `files_cache` for `struct file` and `inode_cache` for `struct inode_data`. You can get the slabs on your local machine by running `sudo cat /proc/slabinfo` in your shell.

Each cpu (hardware thread) contains its own linked list of caches. This is the reason why you might see exploits setting affinity to a particular cpu. Each cache contains 3 more linked lists, namely: 
- `slabs_full`: contains slabs that are completely full (no memory left)
- `slabs_partial`: contains slabs that are partially full (some memory available)
- `slabs_free`: contains slabs that are completely empty (can be re-used or returned to page allocator)

```
+-----------+                   +-------+                   +-----------+
| lastcache | ----------------> | cache | ----------------> | nextcache |
+-----------+                   +-------+                   +-----------+
                                  / | \
                  _______________/  |  \_________________
                 /                  |                    \
                /                   |                     \
               /                    |                      \
    +------------+          +---------------+            +------------+
	| slabs_full |          | slabs_partial |            | slabs_free |
    +------------+          +---------------+            +------------+
          |                         |                           |
          |                         |                           |
          v                         v                           v
      +-------+                 +-------+                   +-------+
      | slabs |                 | slabs |                   | slabs |
      +-------+                 +-------+                   +-------+
          |                         |                           |
          |                         |                           |
          v                         v                           v
      +-------+                 +-------+                   +-------+
      | pages |                 | pages |                   | pages |
      +-------+                 +-------+                   +-------+  
        /  \                      /  \                        /  \
       /    \                    /    \                      /    \
      /      \                  /      \                    /      \
  +-----+  +-----+          +-----+  +-----+            +-----+  +-----+
  | obj |  | obj |          | obj |  | obj |            | obj |  | obj |
  +-----+  +-----+          +-----+  +-----+            +-----+  +-----+
```
[Image Source](https://www.kernel.org/doc/gorman/html/understand/understand-html037.png)

This is the core mechanism used in `SLAB` and `SLUB` allocators. This leads to lesser fragmentation and scales well with more memory. Since the slab allocator holds onto some empty slabs, the allocation is fast and doesn't always have to fallback on the page allocator.

### Some API functions
- `kmalloc_cache_create()` - Create a new cache for an object and add it to the global list of caches
- `kmalloc_cache_destroy()` - Remove cache from global list of caches and frees slabs held by cache
- `kmem_cache_alloc()` - Allocates memory from a given cache
- `kmem_cache_free()` - Frees memory back to the cache

[caches and SLUB allocator](https://sam4k.com/linternals-memory-allocators-0x02/)


## SLAB

Note: `slab` is a structure consisting of page(s) whereas, `SLAB` is a slab allocator

SLAB allocator is the first allocator to implement caching through kmalloc-caches. It speeds up (de)allocation of frequently used objects. The path for allocation looks something like:
- Traverse the current cpu's cache list and find required cache
- Search the partial slabs list and get the first one
	- if no slab is found in partial list, search free list
	- if no slab is found in free list, then allocate a slab and add it to the free list
- Finds first free "slot" in the slab and returns that
- Marks the "slot" as used

Although the SLAB allocator increased performance and reduced fragmentation, it had some pitfalls. For systems with a large number of cpus, there exists queues per node per cpu. In such cases, the allocator uses up a lot of memory on startup. 

[Paper on SLAB allocator](https://people.eecs.berkeley.edu/~kubitron/courses/cs194-24-S13/hand-outs/bonwick_slab.pdf)
[Kernel docs on SLAB allocator](https://www.kernel.org/doc/gorman/html/understand/understand011.html)


## SLUB

SLUB was designed as a drop-in replacement to the SLAB allocator. It simplified the implementation, getting rid of complex queues and metadata. Another major change is that the object freelist is stored inline, in the freed objects itself. SLUB also added support for merging slabs, to reduce memory overhead. This is done implicitly. Objects of similar sizes are cached together unless explicitly specified otherwise. This is known as cache aliasing, where a cache, actually uses the general purpose cache to back allocations. Other than these I can't think of any other major changes between SLAB and SLUB from an exploitation point of view.

You can find cache aliases by running `ls -l /sys/kernel/slab/`.  The symlinks indicate aliasing. Every entry with the same symlink destination, indicate that they are backed by the same cache.

`kmalloc()` is now just a wrapper to `kmem_cache_alloc_trace()`. Similarly `kfree()` uses `kmem_cache_free()` internally.  The size requested is used to determine which general purpose cache can be used to allocate it. `kmem_cache_alloc()` should be used when requesting allocation from a particular cache.

[Presentation on SLAB and SLUB](https://events.static.linuxfound.org/images/stories/pdf/klf2012_kim.pdf)
[Presentation on SLOB, SLAB and SLUB](https://events.static.linuxfound.org/sites/events/files/slides/slaballocators.pdf)
[Structures in SLUB allocator](https://github.com/ocastejon/linux-kernel-learning/blob/main/notes/slab-allocator.md)


## Buddy allocator

The buddy allocator a.k.a the binary buddy allocator, or simply the page allocator, takes on the role of allocating physical pages. It's API is used by the slab allocators and `vmalloc()` internally. It is the most low level memory allocator. The return value is usually `struct *page` or the starting virtual address of the pages. Every physical page in use has an associated `struct page`, to keep track of metadata. Multiple pages part of the same `struct page`.

The allocation is based on order specified, similar to slab order, where order `n` gets you 2<sup>n</sup> pages. On freeing pages, it doesn't destroy the page table entry but rather keeps the page for future allocations. 

- Pages of same order are grouped into pairs, known as buddies
- When a block is freed, its buddy is checked. If the buddy has already been freed, then they are merged into a block of higher order
- The merging is attempted continously until block of `MAX_ORDER` is reached
- During allocation, when block of requested order is present, it is returned as is
- If not, a block of higher order is split iteratively until required order is reached. The remaining blocks from splitting, are added to the freelist

Allocating pages of order 1, when there are only pages of order 3 available:

```
      order    +=================+                  Requesting <--+
        |      |        0        |                    process     |
        |      +=================+                                |
        |      |        1        |<-------------------+           |
        |      +=================+                    |           |
        |      |        2        |<---------+      +-----+     +-----+
        |      +=================+          |      | 2^1 |<-+->| 2^1 |
        |      |        3        |--+       |      +-----+  |  +-----+
        |      +=================+  |  +---------+     +---------+
        |      |        .        |  |  |   2^2   |<-+->|   2^2   |           
        |      |        .        |  |  +---------+  |  +---------+
        |      |        .        |  |     +-------------------+
        |      +=================+  +---->|     2^3 block     |  
        |      |    MAX_ORDER    |        +-------------------+
	    v      +=================+
```
[Image source](https://www.kernel.org/doc/gorman/html/understand/understand-html030.png)

### Some API functions
- `alloc_pages()` - Allocates 2<sup>order</sup> number of pages and returns a `struct page`
- `get_free_page()`- Allocates a single page, zeroes it and returns virtual address
- `__free_pages()` - Free 2<sup>order</sup> number of pages from given `struct page`
- `free_page()` - Free a page from the given virtual address

[Kernel docs for buddy allocator](https://www.kernel.org/doc/gorman/html/understand/understand009.html)
[Paper on buddy allocator](https://students.mimuw.edu.pl/ZSO/Wyklady/06_memory2/BuddySlabAllocator.pdf)


## Exploitation primitives & techniques

#### Heap overflow
This primitive allows overwriting neighboring objects in a slab. Usually in such cases, we aim to get an object with function pointers or pointers in general, in hopes of overwriting them for stronger primitives such as rip control or arbitrary r/w.
#### Use after free
This can also be caused by an incorrect free primitive. This primitive allows us to hold a reference to a freed object. Allocating a different object in the same cache, allows us to cause type confusion. This is because we have 2 references to the same memory but through different contexts. Use the type confusion to control some member in the object and build stronger primitives from there.
#### Freelist poisoning
This technique can be used to hijack the object freelist in the SLUB allocator since it stores the freelist inline. This technique is partially mitigated through `CONFIG_SLAB_FREELIST_HARDENED`, although it can be bypassed. More about that in the upcoming sections. This technique allows allocation of arbitrary kernel memory.
#### Spray and pray
Heap sprays are a common technique used to increase exploit reliability. It just means spamming a lot of allocations of a particular object to counteract randomness caused by mitigations and system noise (allocations beyond our control). In some cases, the spray has to be controlled to achieve maximum reliability.
#### Cross-cache
This is a somewhat recent technique where vulnerable objects can overflow onto objects in another cache, or UAF objects can be allocated in a different cache. This requires careful manipulation of the slab (and page) allocator. Essentially, we cause an entire slab containing our vulnerable object to be freed and re-used by another cache. When the cross-cache is to a cache of different order, it requires manipulation of the page allocator as well.

[kernelCTF cookbook](https://docs.google.com/document/d/1a9uUAISBzw3ur1aLQqKc5JOQLaJYiOP5pe_B4xCT1KA/edit#heading=h.nqnduhrd5gpk)

## Some hardening features

#### CONFIG_SLAB_FREELIST_RANDOM
This config option in the kernel randomizes the order of the slab freelist at runtime. The order of allocation in the slab is non-deterministic. Exploits which rely on overflowing into neighboring objects or require object at specific alignment in a slab lose reliability.  Heap spray can be used to counteract this.
#### CONFIG_SLAB_FREELIST_HARDENED
This config option requires the SLUB allocator. It encrypts the inline freelist pointers present in freed objects with a random 8 byte value, generated at runtime. The encryption is a basic bitwise xor operation. This prevents information leak and hijacking the freelist. It can be bypassed by getting a heap leak and an encrypted pointer leak and xoring both to get the encryption key. 
#### CONFIG_MEMCG_KMEM
Although strictly not a hardening config option, it makes exploitation ever so harder. This causes some commonly used objects, to be put in `kmalloc-cg-x` caches instead of the usual `kmalloc-x` caches. This is because these objects are allocated with the flag `SLAB_ACCOUNT`. This can be overcome using cross-cache.
#### CONFIG_RANDOM_KMALLOC_CACHES
This config option creates multiple copies of `kmalloc-cg-x` and `kmalloc-x` caches. The copy of the cache chosen for allocation, depends on a random seed and the return address for `kmalloc()`. This reduces exploit reliability a lot. However cross-cache can be used to overcome this.
#### CONFIG_SLAB_VIRTUAL
This config option still hasn't been merged with mainline yet. It aims to prevent cross-cache and UAFs in general by preventing re-use of the same virtual address for a slab across different caches. After looking at a bunch of `_mitigation` exploits for kernelctf, I don't see any bypasses for this yet. Please correct me if I'm wrong.


## Objects

You can use tools such as `pahole` and [kernel_obj_finder](https://github.com/chompie1337/kernel_obj_finder) to get objects available in the build you're working with.
#### Elastic objects
These objects are called so, because they can be allocated in various general purpose caches. Although the introduction of `CONFIG_MEMCG_KMEM`, moved most of them to the `kmalloc-cg-x` caches. These objects are useful because of their dynamic size and user controlled content.

Some elastic objects are:

- `struct msg_msg`
	- allocate: `msgsnd()`
	- free: `msgrcv()`
	- size: `0x40 - 0x1000`
```c
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;
	/* the actual message follows immediately */
};
```

- `struct msg_msgseg`
	- allocated and freed using same path as `msg_msg`
	- allocation occurs when msg datalen > 0xfc8
	- the remaining bytes are put in a`struct msg_msgseg`
	- size: `0x10-0x1000`
```c
struct msg_msgseg {
	struct msg_msgseg *next;
	/* the next part of the message follows immediately */
};
```

- `struct simple_xattr`
	- allocate: `setxattr()` on a `tmpfs` filesystem
	- free: `removexattr()`
	- size: `0x30 - ?`
```c
struct simple_xattr {
	struct rb_node rb_node;
	char *name;
	size_t size;
	char value[];
};
```

- `struct user_key_payload`
	- allocate: `add_key()` 
	- free: `keyctl_revoke()` + `keyctl_unlink()`
	- size: `0x20 - ?`
```c
struct user_key_payload {
	struct rcu_head rcu;
	unsigned short  datalen;
	char		    data[] __aligned(__alignof__(u64));
}
```

#### Critical objects
Being able to overwrite or control these objects usually leads to privilege escalation. These objects usually contain flags that control permissions. Since they are critical, they are usually allocated in dedicated caches with `SLAB_NOMERGE`, `SLAB_ACCOUNT` flags.

Some critical objects are:
- `struct cred`
	- private cache: `cred_jar`
	- allocate: `fork()`,`clone()`
	- free: `exit()`
	- size: `0xa0`
	- overwrite `uid`,`gid` members for changing privileges of process<br>
```c <br>
struct cred {
	atomic_long_t usage;
	kuid_t uid; /* real UID of the task */
	kgid_t gid; /* real GID of the task */
	kuid_t suid; /* saved UID of the task */
	kgid_t sgid; /* saved GID of the task */
	kuid_t euid; /* effective UID of the task */
	kgid_t egid; /* effective GID of the task */
	kuid_t fsuid; /* UID for VFS ops */
	kgid_t fsgid; /* GID for VFS ops */
	unsigned securebits; /* SUID-less security management */
	kernel_cap_t cap_inheritable; /* caps our children can inherit */
	kernel_cap_t cap_permitted; /* caps we're permitted */
	kernel_cap_t cap_effective; /* caps we can actually use */
	kernel_cap_t cap_bset; /* capability bounding set */
	kernel_cap_t cap_ambient; /* Ambient capability set */

#ifdef CONFIG_KEYS
	unsigned char jit_keyring; /* default keyring to attach requested
* keys to */
	struct key *session_keyring; /* keyring inherited over fork */
	struct key *process_keyring; /* keyring private to this process */
	struct key *thread_keyring; /* keyring private to this thread */
	struct key *request_key_auth; /* assumed request_key authority */
#endif

#ifdef CONFIG_SECURITY
	void *security; /* LSM security */
#endif

	struct user_struct *user; /* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct ucounts *ucounts;
	struct group_info *group_info; /* supplementary groups for euid/fsgid */
/* RCU deletion */
	union {
		int non_rcu; /* Can we skip RCU deletion? */
		struct rcu_head rcu; /* RCU deletion hook */
	};
} __randomize_layout;
```

- `struct file`
	- private cache: `files_cache`
	- allocate: `open()`
	- free: `close()`
	- size: `0x300`
	- overwrite `f_mode` to change file access permissions<br>
```c <br>
struct file {
	union {
		/* fput() uses task work when closing and freeing file (default). */
		struct callback_head f_task_work;
		/* fput() must use workqueue (most kernel threads). */
		struct llist_node f_llist;
		unsigned int f_iocb_flags;
	};

	/*
	* Protects f_ep, f_flags.
	* Must not be taken from IRQ context.
	*/
	spinlock_t f_lock;
	fmode_t f_mode;
	atomic_long_t f_count;
	struct mutex f_pos_lock;
	loff_t f_pos;
	unsigned int f_flags;
	struct fown_struct f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	struct path f_path;
	struct inode *f_inode; /* cached value */
	const struct file_operations *f_op;
	u64 f_version;

#ifdef CONFIG_SECURITY
	void *f_security;
#endif

	/* needed for tty driver, and maybe others */
	void *private_data;

#ifdef CONFIG_EPOLL
	/* Used by fs/eventpoll.c to link all the hooks to this file */
	struct hlist_head *f_ep;
#endif /* #ifdef CONFIG_EPOLL */

	struct address_space *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err; /* for syncfs */
} __randomize_layout
```



## Some cool challenges

- [Pawnyable](https://pawnyable.cafe/linux-kernel/) (heap overflow, UAF)
- [CISCN2017 - baby driver](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/kernel/CISCN2017-babydriver) (UAF)
- [CUCTF2019 - hotrot](https://github.com/CUCyber/cuctf-2020-challenges/tree/main/binary-exploitation/Hotrod/distributed) (userfaultfd race + UAF)
- [bi0sCTF2022 - k32](https://github.com/teambi0s/bi0sCTF/tree/main/2022/Pwn/k32/handout) (heap overflow) (shameless plug :D)
- [backdoorCTF2023 - empdb](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/BackdoorCTF/2023/pwn/EmpDB) (userfaultfd race + freelist poisoning)

## The end
I started writing this for my reference in the future, but it turned into a blog post. I will probably update this few times until I'm satisfied with it. I would like to take this oppurtunity to thank few people, for motivating and helping me with learning Linux Kernel Exploitation: [Cyb0rG](https://twitter.com/_Cyb0rG), [3agl3](https://twitter.com/3agl31) & [kylebot](https://twitter.com/ky1ebot)