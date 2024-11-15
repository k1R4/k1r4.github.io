---
layout: post
title:  "virtio-note [bi0sCTF24]"
date:   2024-02-28 15:59:00 +0530
categories: pwn qemu vm-escape author
---

## Challenge Description

&nbsp;&nbsp;&nbsp; Heap notes have become very repitive :(<br>
&nbsp;&nbsp;&nbsp; How about adding a few layers of ~~abstraction~~ fun in between :D

Handout has bzImage, rootfs.ext3, run.sh, qemu-system-x86_64, bios binaries and source code of the virtio device along with the patch file. Additionally a README.md file is provided to help participants replicate the QEMU build and the kernel used.

## Initial Analysis

### General observations
Seccomp is compiled in as seen is README.md and `-sandbox on,spawn=deny` is added as a flag in run.sh, this disables many syscalls and was turned on to prevent abusing `one_gadget`. It can also be seen that QEMU has been compiled statically, which reduces the amount of leaks needed.

### VirtIO

The device is a virtio PCI device which means it behaves quite differently from regular PCI devices. VirtIO is an abstraction layer that makes writing devices and drivers easier. It provides a standard base that can be used for a variety of devices. Most of the heavy lifting is done by the hypervisor and the guest OS (Kernel). Since virtio is ingrained into the kernel, the driver for it will have to be in the kernel, which can be a loadable module. More information regarding VirtIO can be found [here](https://blogs.oracle.com/linux/post/introduction-to-virtio).

### VirtQueues

This is the mechanism that allows for communication between device and driver. Here are some key points that I noted down when reading about VirtQueues:
- virtqueues are structures that are used for communication between driver and device
	- driver runs on guest
	- device runs on host
- virtqueues are used bidirectionally to/from guest
- guest driver puts requests into sg list and queues it
- after a bunch of requests it kicks (writes into device register)
	- kick after multiple requests to improve throughput and latency
- host consumes requsets, processes them
- pushes back the requests as response
- notifies guest through interrupt or similar mechanisms
- one device can have multiple virtqueues

Before diving into the code, it is recommended to go through [this presentation](http://retis.sssup.it/luca/KernelProgramming/Slides/kp_virtio.pdf). It helped me a lot in understanding virtqueues.

### Device implementation

`virtio-note-pci.c` can mostly be ignored since its only creating a virtio PCI device from the standard `virtio-note` device.

```c
typedef struct VirtIONote {
    VirtIODevice parent_obj;
    VirtQueue *vnq;
    char *notes[N_NOTES];
} VirtIONote;
```
- QEMU uses an object model, so `VirtIONote` inherits the base class `VirtIODevice`. More information about QEMU Object Moduel (QOM) can be found [here](https://qemu-project.gitlab.io/qemu/devel/qom.html).
- The `virtio-note` device has a single virtqueue, `vnote->vnq`
- It has an array of pointers that each point to a "note"<br><br>


```c
static void virtio_note_device_realize(DeviceState *dev, Error **errp) {
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIONote *vnote = VIRTIO_NOTE(dev);
    virtio_init(vdev, VIRTIO_ID_NOTE, 0);
    vnote->vnq = virtio_add_queue(vdev, 4, virtio_note_handle_req);
    for(int i = 0; i < N_NOTES; i++)
    {
        vnote->notes[i] = calloc(NOTE_SZ, 1);
        if(!vnote->notes[i])
        {
            virtio_error(vdev, "Unable to initialize notes");
            return;
        }
    }
}
```
- This function runs during initial setup of the device
- It creates a virtqueue, `vnote->vnq` and registers a handler for it, `virtio_note_handle_req()`
- Finally the pointer array, `vnote->notes`, is initialized with calloc-ed heap chunks<br><br>

```c
typedef struct req_t {
    unsigned int idx;
    hwaddr addr;
    operation op; //operation is an enum
} req_t;

static void virtio_note_handle_req(VirtIODevice *vdev, VirtQueue *vq) {
    VirtIONote *vnote = VIRTIO_NOTE(vdev);
    VirtQueueElement *vqe = 0;
    req_t *req = 0;

    while(!virtio_queue_ready(vq)) {
        return;
    }

    if (!runstate_check(RUN_STATE_RUNNING)) {
        return;
    }

    vqe = virtqueue_pop(vq, sizeof(VirtQueueElement));
    if(!vqe) goto end;

    if(vqe->out_sg->iov_len != sizeof(req_t)) goto end;
    req = calloc(1, sizeof(req_t));
    if(!req) goto end;
    if(iov_to_buf(vqe->out_sg, vqe->out_num, 0, req, vqe->out_sg->iov_len) != sizeof(req_t)) goto end;

    if(!vnote->notes[req->idx])
    {
        virtio_error(vdev, "Corrupted note encountered");
        goto end;
    }

    switch(req->op)
    {
        case READ:
            cpu_physical_memory_write(req->addr, vnote->notes[req->idx], NOTE_SZ);
            break;

        case WRITE:
            cpu_physical_memory_read(req->addr, vnote->notes[req->idx], NOTE_SZ);
            break;

        default:
            goto end;
    }

    virtqueue_push(vq, vqe, vqe->out_sg->iov_len);
    virtio_notify(vdev, vq);

end:
    g_free(vqe);
    free(req);
    return;
}
```
- The handler only processes one element in the virtqueue per kick
- Copies the buffer from the sg list to a temporary request buffer
- Checks for non-null pointer at `vnote->notes[req->idx]`
- Based on the operation,
    - READ => copies 0x40 bytes from `vnote->notes[req->idx]` to physical address of the guest given by `req->addr`
    - WRITE => similarly copies 0x40 bytes from `req->addr` to `vnote->notes[req->idx]`
- Finally puts the element back into virtqueue and notifies guest


## Bug

There is a clear Out Of Bounds (OOB) pointer access bug in `virtio_note_handle_req()`
```c
if(!vnote->notes[req->idx])
{
    virtio_error(vdev, "Corrupted note encountered");
    goto end;
}
```
The above check only prevents null derefences. There is no bounds check before accessing `vnote->notes[req->idx]`. This allows reading from/writing to any pointer relative to `vnote->notes`. This bug provides a powerful primitive. Since its my first time working with QEMU, I decided to go with a easy bug.

## Exploit Strategy

First off a kernel driver has to be created to talk to the virtio device. The exploit itself can be part of the driver or separate. I chose the latter approach since it makes the exploit cleaner and easier to understand. Here is the approach I used:

- Read double heap pointer to get heap leak of neighborhood
- Calculate address of `VirtIONote`(vnote) object from leak
- Setup arbitrary r/w primitive
    - Overwrite a trivial heap pointer with `vnote->notes`
    - Index relative to `vnote->notes` to access previously written pointer
    - Write required address at said index
    - Access `vnote->notes[0]` for read/write at required address
- Leak virtqueue object address by reading `vnote->vnq`
- Leak code address by reading any heap address with a function pointer
- Calculate PIE base using leak
- Use appropriate gadgets to craft open, read, write ropchain
- Place ropchain in some trivial place in the heap, I did it at `vnote->notes[3]`
- Place a small ropchain at the start of `vnote` to pivot to the main ropchain
- Overwrite `vnote->vnq->handle_output` with appropriate stack pivoting gadget
- Since the first argument to `virtio_note_handle_req()` is `VirtIODevice *vdev` which is at the start of `VirtIONote`, pivoting there is easy
- Then the ropchain there to pivots to main ropchain
- Having a smaller ropchain at start of `vnote`, corrupts less of it, reducing likelihood of segfault
- Main ropchain prints the flag and cleanly exits

## Conclusion

Some of the solutions used shellcode by placing it in rwx JIT memory mappings, which is a cool approach that I didn't think of. This was my first time working on a QEMU challenge and it seems like an interesting target!

You can find the exploit [here](https://gist.github.com/k1R4/790f17cf583b8431d47f3c334c9576f4)<br>
You can find the driver source [here](https://gist.github.com/k1R4/d4953700e6173ef0d356d407699b51eb)

Flag: `bi0sctf{virt10_n0t3_b3tt3r_7han_h34p_n0t3_51a15b2f}`