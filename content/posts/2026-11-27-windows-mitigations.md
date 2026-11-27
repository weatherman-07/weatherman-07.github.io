+++
title = "the windows mitigation arms race: how the kernel got hard to own (and why it still gets owned)"
date = 2026-11-27
draft = false
summary = "A deep technical walkthrough of every major Windows kernel mitigation from DEP to HVCI to VBS enclaves, how they were bypassed, and why BYOVD dominates modern attacks."
tags = ["windows", "kernel", "exploitation", "mitigations", "byovd", "hvci", "smep", "cet", "vbs"]
+++

If you've been doing Windows offensive research long enough, you know there are two timelines. The old one where shellcode just ran, and the new one where you need a PhD just to get code execution and even then the hypervisor says no. This post is my attempt to lay out the complete story of how Windows incrementally made itself harder to exploit, the interesting bypasses that came out of each era, and why BYOVD is now the dominant kernel bypass technique even though none of the underlying mitigations were actually defeated.

This is not a quick overview. I went deep into Connor McGarr's entire exploit dev series, the ALPC exploitation work from y3a, Doyensec's SFAPE enclave research, g3tsyst3m's BYOI writeup, and a bunch of other sources to put this together. If you want the original technical depth on any single piece of this, go read those. This post is trying to give you the full arc in one place, connecting everything from stack overflows in 2003 all the way through VTL1 code execution in 2026.

We're going to cover a lot: x64 paging and PTEs, DEP, ASLR, ROP chains, SMEP, SMAP, PTE manipulation, CFG and XFG, ACG, VBS, HVCI, EPT, MBEC, data-only attacks, kernel pool exploitation, ALPC primitives, CET and shadow stacks, BYOVD, BYOI, and VBS enclaves. Each of these topics could fill its own series of posts. I'm going to give you enough depth to actually understand what's going on, not just name-drop acronyms.

---

## x64 Paging: The Foundation You Need to Understand Everything Else

Before any of the mitigations make sense, you need to understand how virtual memory works on x64. This stuff is the foundation for DEP, ASLR, SMEP, PTE manipulation, HVCI, and every other memory-based protection. If you already know paging cold, skip ahead. If not, this is the most important section in the post.

<img src="/assets/media/windows-mitigations/paging-overview.png" alt="Virtual memory: each process has its own virtual address space that maps to physical memory" style="max-width:100%;border-radius:6px;margin:1.5em auto;display:block;border:none">

x64 uses a four-level paging structure. When the CPU needs to translate a virtual address to a physical one, it walks through four tables: the Page Map Level 4 (PML4), the Page Directory Pointer Table (PDPT), the Page Directory Table (PDT), and the Page Table (PT). Each level is indexed by nine bits from the virtual address. The final 12 bits are the page offset within the physical page.

Here is how a 64-bit virtual address gets broken down:

```
Bits 63-48: Sign extension (must be 0xFFFF or 0x0000, enforced by hardware)
Bits 47-39: PML4 index (9 bits = 512 entries)
Bits 38-30: PDPT index (9 bits = 512 entries)
Bits 29-21: PDT index  (9 bits = 512 entries)
Bits 20-12: PT index   (9 bits = 512 entries)
Bits 11-0:  Page offset (12 bits = 4096 bytes per page)
```

<img src="/assets/media/windows-mitigations/paging-4kb-translation.png" alt="Intel 4-Kbyte Page Translation in Long Mode: CR3 -> PML4 -> PDPT -> PDT -> PT -> Physical Page" style="max-width:100%;border-radius:6px;margin:1.5em auto;display:block;border:none">

The CR3 register holds the physical address of the PML4 table. Each entry in each table is 8 bytes. So a full page table covers 512 * 512 * 512 * 512 * 4096 = 256 TB of virtual address space per privilege level, which matches what x64 supports.

Each entry at the page table level is a Page Table Entry (PTE). The PTE is where the magic and all the mitigations live. Here are the important bits in a PTE:

- **Bit 0 (P)**: Present. If 0, the page is not in memory (triggers a page fault).
- **Bit 1 (R/W)**: Read/Write. If 0, the page is read-only. If 1, it's writable.
- **Bit 2 (U/S)**: User/Supervisor. If 0, only ring 0 (kernel) can access this page. If 1, user mode can access it.
- **Bit 5 (Accessed)**: Set by CPU when the page is read.
- **Bit 6 (Dirty)**: Set by CPU when the page is written.
- **Bits 51-12 (PFN)**: Page Frame Number. PFN * 0x1000 = physical address of the page.
- **Bit 63 (NX/XD)**: No-Execute / Execute-Disable. If set, code cannot execute from this page.

The canonical addressing rule is also worth understanding. Bits 63 through 48 must all be copies of bit 47. This means kernel addresses (bit 47 = 1) look like `0xFFFFxxxxxxxxxxxx` and user addresses (bit 47 = 0) look like `0x0000xxxxxxxxxxxx`. Any address that violates this rule causes a general protection fault. This canonical form enforcement is what makes the Windows kernel/user split visually obvious in addresses.

Now, the Page Frame Number. The PFN field (bits 51-12) contains the index of the physical page. To get the physical address: take bits 51-12 of the PTE, multiply by 0x1000 (or just shift left 12 bits). That's your physical page. Add the 12-bit page offset from the original virtual address and you have the physical address.

### Finding PTEs: MiGetPteAddress

To manipulate a PTE for a given virtual address, you need to find where that PTE lives in memory. The Windows kernel provides an internal function called `MiGetPteAddress` that does exactly this.

The PTE for a virtual address is itself stored at a virtual address. All the page tables are mapped into a specific region of kernel virtual address space. This region is controlled by a "PTE base" value. Before Windows 10 1607 (RS1), this base was hardcoded at `0xFFFFFF6800000000`. That meant if you knew any virtual address, you could calculate the address of its PTE with simple arithmetic:

```
PTE address = ((VA >> 9) & 0x7FFFFFFFF8) + 0xFFFFFF6800000000
```

This is why the formula works: you're taking your virtual address, shifting right by 9 to account for the 12-bit page offset and 3 bits of PT index, masking to get the right bits, and adding the base.

In RS1, Microsoft randomized the PTE base on every boot. The static formula stopped working. Now you need to leak the PTE base before you can do anything useful with PTE manipulation.

Where do you get the PTE base? From `MiGetPteAddress` itself. At offset `+0x13` inside `MiGetPteAddress`, there's a `MOV RAX, [address]` instruction where the address being loaded is the PTE base. If you have an arbitrary read primitive in the kernel, you read the kernel virtual address of `MiGetPteAddress + 0x13`, dereference it, and you have your PTE base.

This is the info leak path that became necessary after RS1: get a kernel module base (via whatever info leak is available), calculate the offset to `MiGetPteAddress`, read offset `+0x13`, dereference to get the PTE base, and now you can find PTEs for any virtual address.

### Large Pages and Superpages

One important optimization worth knowing: Windows can use large pages (2MB) or huge pages (1GB) where a PDT or PDPT entry maps directly to a physical page, skipping lower levels of the paging hierarchy. The PTE structure for a large page entry is a bit different. The key bit to watch is bit 7 (PS, Page Size) in the PDT entry. If set, the PDT entry maps a 2MB large page directly instead of pointing to a PT. Large pages in the kernel are significant for performance, but they also affect PTE manipulation since there is no PT-level entry to modify.

---

## DEP and NX: The Mitigation That Made Shellcode Stop Working

Data Execution Prevention arrived in Windows XP SP2 in 2004 and was the first real push against arbitrary code execution. The idea is conceptually simple: memory pages can be writable or executable, but marking a page as both is prohibited. When you overflow a stack and redirect control to shellcode sitting in the data segment or stack, the CPU checks the NX bit (bit 63 in the PTE), finds it set, and throws a protection fault. Process terminated.

The hardware prerequisite is the NX bit support in the CPU, which requires the IA32_EFER MSR (Model Specific Register) to have the NXE bit set. All modern x64 CPUs support this. AMD introduced it first (calling it the NX bit), Intel followed with XD (Execute Disable). Same thing.

Windows implements DEP at two granularities. The hardware-enforced version (HW-DEP) uses the CPU NX bit via PTEs and covers every page. There's also a software version (SW-DEP) that only covers exception handlers and is much weaker; this was for older CPUs that lacked NX support. If you're doing any modern exploit work, you're dealing with HW-DEP exclusively.

For user-mode processes, DEP has four modes:

- **AlwaysOn**: Every process gets DEP, no exceptions. This is the default on 64-bit Windows.
- **AlwaysOff**: No process gets DEP. Only exists for compatibility testing.
- **OptIn**: Only specific processes get DEP (those compiled with /NXCOMPAT or explicitly opted in).
- **OptOut**: All processes get DEP except those on an exclusion list.

On 64-bit Windows, DEP is essentially always on for user mode. There's no meaningful way to disable it via the linker flag or the API when running 64-bit code. The `/NXCOMPAT` flag only actually matters for 32-bit (WOW64) processes.

The kernel-mode story took longer to nail down. The issue was that early Windows versions allocated kernel pool memory as RWX (readable, writable, and executable). This meant kernel exploits could write shellcode to pool memory and execute it directly. The `NonPagedPool` pool type was the main offender. Microsoft introduced `NonPagedPoolNx` in Windows 8 and started migrating kernel allocations to use it. By Windows 8.1, most kernel components used the Nx variant by default.

What this created is a rough timeline. Before Windows 8, kernel exploits often looked like:

1. Trigger pool overflow to write shellcode into pool memory
2. Pool memory is executable, so redirect execution to shellcode
3. Shellcode runs at ring 0, full kernel privileges

After Windows 8 with NonPagedPoolNx:

1. Trigger pool overflow
2. Pool memory is not executable anymore
3. You need an alternative execution method (hello ROP)

DEP forced the entire field of exploitation to evolve. It didn't stop exploitation; it made shellcode execution specifically stop working and pushed everyone toward Return-Oriented Programming.

---

## ROP: Turning the Program Against Itself

Return-Oriented Programming emerged as the response to DEP, and it's genuinely clever. The key insight is that executable code already exists in the process (or kernel). The `.text` sections of ntdll.dll, kernel32.dll, ntoskrnl.exe, and every other loaded module are full of code. You can't add new code, but you can redirect execution through existing code in ways the original authors never intended.

A ROP gadget is a short sequence of instructions ending with a `RET` instruction. Here's a simple example:

```asm
pop rax
ret
```

This gadget pops a value off the stack into RAX, then returns (pops the next value off the stack into RIP). If you control the stack, you can chain these gadgets. Put gadget addresses on the stack one after another, and each `RET` instruction chains to the next gadget. By carefully selecting gadgets and the data between them, you can build arbitrary computations entirely from pre-existing code.

### Building a ROP Chain to Defeat DEP

The classic user-mode ROP chain targets `VirtualProtect()` or `VirtualAlloc()` to flip memory permissions. The goal: mark your shellcode page as executable, then jump to it.

A `VirtualProtect` call needs four arguments:

```
VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
```

On x64 Windows, the first four arguments go in RCX, RDX, R8, and R9 respectively. So you need ROP gadgets to:

1. Load the address of your shellcode into RCX
2. Load the size (e.g., 0x1000) into RDX  
3. Load PAGE_EXECUTE_READWRITE (0x40) into R8
4. Load a writable address for the old protection into R9
5. Call VirtualProtect

For step 5, since you can't do an indirect call without CFG checking it, you use the IAT (Import Address Table) entry for VirtualProtect. The IAT entry contains the address of VirtualProtect. You put a gadget like `JMP [rbx]` where RBX points to the IAT entry, and you end up calling the real function.

Another classic approach: `WriteProcessMemory()`. Instead of making your shellcode page executable, write your shellcode into memory that's already executable. The `.text` section of the process is both readable and executable. If you can write arbitrary data there, you can place shellcode in existing executable memory without touching permissions at all.

```
WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
```

Write to a location in the process's own executable memory. This bypasses DEP entirely because the target memory was already executable before you wrote to it. This technique is particularly useful for kernel exploits where you want to avoid permission changes that might trigger monitoring.

### The Stack Preservation Problem

A critical challenge in ROP: the stack pointer (RSP) must stay valid throughout the chain. If RSP points to non-mapped memory, the first `RET` causes a page fault and the chain fails. This is why ROP chain construction requires careful layout of the fake stack.

When a stack overflow gives you control of RIP, the RSP at that moment points somewhere on the stack. As each ROP gadget executes, RSP advances (each `RET` adds 8 to RSP). Your gadget data needs to be laid out at increasing addresses from the initial RSP value. If you misalign anything, the chain falls apart.

For kernel exploits specifically, the stack situation is more complex. The kernel uses separate stacks for interrupt handling (ISR stacks), DPC stacks, and normal thread execution stacks. When you spray shellcode or build ROP chains in kernel exploits, you need to target the right stack.

---

## ASLR and kASLR: Making You Buy Two Bugs

Address Space Layout Randomization appeared in Windows Vista and randomizes where code and data get loaded. Without ASLR, if you need a gadget at a specific offset inside ntdll.dll, that offset is always the same across machines running the same OS version. With ASLR, the base address of ntdll.dll changes on every boot. Your hardcoded address becomes a random number.

The randomization works at the module level. Each DLL and EXE gets a random base address chosen at boot time. The randomness comes from the system PRNG and uses a certain number of entropy bits for the offset. On 64-bit Windows, ASLR for 64-bit modules has about 17-19 bits of entropy, which means roughly 128K-512K possible base addresses. That sounds like a lot, but in practice it's not brute-forceable locally since any miss crashes the process.

The critical detail: Windows randomizes per reboot, not per process launch. All processes share the same module layouts after boot. This means if you leak the base address of ntdll.dll from one process, every other process on the same system (same boot) has ntdll.dll at the same address. One leak, all processes exploitable.

### kASLR: The Kernel Module Problem

Kernel modules (ntoskrnl.exe, win32k.sys, ndis.sys, etc.) also get ASLR'd. This is kASLR. Before Windows 8.1, the APIs `NtQuerySystemInformation` with `SystemModuleInformation` (class 11) and `EnumDeviceDrivers()` would return kernel module base addresses directly to any user-mode caller. These were the go-to info leak primitives.

```c
NtQuerySystemInformation(
    SystemModuleInformation,  // 0x0B
    pBuffer,
    bufferSize,
    &returnLength
);
```

This returned a list of every loaded kernel module with its base address. Instant kASLR bypass. No vulnerability required, just a standard system call.

Microsoft fixed this in Windows 8.1 by restricting `SystemModuleInformation` and related classes to medium integrity or higher. A sandboxed browser renderer process running at low integrity couldn't call it anymore. The fix made kASLR actually meaningful for sandbox escape scenarios.

However, medium integrity processes (which is most things running as a regular user) could still call it up until more recently. Even today there are legitimate query classes that leak useful addresses, though Microsoft has been progressively tightening what's available at which integrity levels.

### The PTE Base Leak: RS1 and the Info Leak Chain

Before Windows 10 1607 (RS1), the PTE base address was fixed at `0xFFFFFF6800000000`. This was well-known and hard-coded in every exploit that did PTE manipulation. The PTE for any virtual address was just an arithmetic calculation away.

RS1 randomized the PTE base. Now, to do PTE manipulation, you need:

1. An arbitrary read in the kernel
2. The address of `MiGetPteAddress` (available from any kASLR bypass that gives you the kernel base)
3. Read `*(MiGetPteAddress + 0x13)` to get the PTE base
4. Use the PTE base in your PTE address calculation

Then you can find the PTE for any virtual address and corrupt it.

The practical implication is that exploiting most Windows kernels from RS1 onward requires at least two separate primitives: an info leak to get kernel addresses, and an arbitrary write (at minimum) to do the actual exploitation. Single-primitive exploits became very rare.

There's another historical note worth knowing about: before RS2, the HAL (Hardware Abstraction Layer) heap was at a predictable location in memory (`0xFFFFFFFFFFD00000`). The HAL heap contained useful data including function pointers. After RS2, this was randomized too, eliminating it as a reliable data leak location.

---

## SMEP: No More Trampoline to User Space

<img src="/assets/media/windows-mitigations/cr4-smep-smap-bits.png" alt="CR4 register layout showing SMEP at bit 20 and SMAP at bit 21" style="max-width:100%;border-radius:6px;margin:1.5em auto;display:block;border:none">

Supervisor Mode Execution Prevention arrived in Intel Ivy Bridge (2012) and AMD's bulldozer architecture around the same time. It's a CPU feature controlled by bit 20 of the CR4 register. When SMEP is enabled, any attempt by kernel code to execute instructions on a page with the U/S bit set (user pages) triggers an immediate fault. No exceptions, no workaround at the instruction level.

Before SMEP, the classic kernel exploit path was elegant:

1. Allocate memory in user mode via `VirtualAlloc()` with PAGE_EXECUTE_READWRITE
2. Write your shellcode to that allocation
3. Find a kernel arbitrary write (or function pointer overwrite) vulnerability
4. Overwrite a kernel function pointer with the user-mode address of your shellcode
5. Wait for the kernel to call that function pointer
6. The kernel jumps to your user-mode shellcode
7. Shellcode runs in ring 0

SMEP kills step 6. The moment the kernel tries to fetch instructions from a page with U/S=1, the CPU faults. The kernel cannot execute user-mode pages, period.

This forced kernel exploit authors to either (a) find kernel-mode shellcode or (b) build kernel ROP chains. Option (b) became the standard approach.

### SMEP Bypass #1: CR4 Flipping

The first SMEP bypass technique was simply disabling SMEP via a kernel ROP chain. CR4 bit 20 is the SMEP enable bit. If you can clear it, SMEP goes away.

```asm
; ROP gadgets to build:
pop rcx
ret
; (put new CR4 value without bit 20 here, e.g., 0x50678)

mov cr4, rcx
ret
; (then jump to user-mode shellcode)
```

The trick: within your kernel ROP chain (before SMEP becomes an issue, since the ROP chain itself runs from kernel-mode executable pages), include gadgets that load a new CR4 value with bit 20 cleared into RCX, then execute `MOV CR4, RCX`. Once that instruction executes, SMEP is disabled system-wide. Then you can branch to user-mode shellcode.

This technique worked for a while. Alex Ionescu presented on SMEP bypasses at Infiltrate 2015, noting that the CR4 flip approach was the main bypass at the time.

Microsoft's response was HyperGuard. When VBS is enabled, the hypervisor monitors changes to CR4 and other sensitive control registers. Any attempt to clear the SMEP bit in CR4 triggers a hypervisor intervention. The CR4 flip SMEP bypass is dead on any system with VBS/HyperGuard enabled.

### SMEP Bypass #2: PTE U/S Bit Manipulation

The more elegant bypass targets the PTE U/S bit directly. SMEP fires when the CPU sees a page with U/S=1 (user page). But the check is done against PTEs in the paging hierarchy. What if you flip the U/S bit in the PTE for your user-mode page from 1 (user) to 0 (supervisor)?

The CPU checks PTEs when walking the page table. If your page's PTE has U/S=0, the page looks like a supervisor page to the CPU. SMEP won't fire because SMEP only triggers on user pages (U/S=1). Your shellcode page now appears to be a supervisor page, and kernel code can execute it.

The critical insight from Connor McGarr's SMEP bypass post: you only need to clear U/S in ONE level of the paging hierarchy. If any level in the hierarchy (PML4E, PDPTE, PDE, PTE) has U/S=0, the effective U/S for the final page is 0. You don't need to find and modify all four levels.

Here's the exploit flow:

1. Get kASLR bypass (kernel module base address)
2. Calculate address of `MiGetPteAddress`
3. Arbitrary read from `MiGetPteAddress + 0x13` to get PTE base
4. Calculate the PTE address for your user-mode shellcode page
5. Arbitrary write to the PTE to clear the U/S bit (bit 2)
6. The page now looks like a supervisor page
7. Use a function pointer overwrite to redirect kernel execution to your user-mode address
8. Kernel executes your shellcode, SMEP doesn't fire

This technique works against SMEP without needing to modify CR4. It requires an arbitrary read (to get the PTE base) and an arbitrary write (to modify the PTE).

This became the dominant kernel exploitation technique for several years. It's elegant, reliable, and doesn't touch any hypervisor-protected state. Until HVCI arrived.

---

## SMAP: And While We're At It, No Reading User Space Either

Supervisor Mode Access Prevention came along with Skylake-era processors and complements SMEP. While SMEP prevents kernel from *executing* user pages, SMAP prevents the kernel from *reading or writing* user pages at all unless a specific flag is set.

The hardware implementation uses CR4 bit 21 (the SMAP enable bit) in combination with the AC (Alignment Check) flag in RFLAGS. When SMAP is enabled:

- If AC flag = 0: kernel cannot access user-mode pages (R/W/X all blocked)
- If AC flag = 1: kernel can access user-mode pages normally

The kernel uses `CLAC` (Clear AC flag) and `STAC` (Set AC flag) instructions to toggle user-mode access. Legitimate kernel code that needs to copy to/from user mode wraps those operations with STAC/CLAC pairs. Any code that doesn't explicitly set AC cannot touch user-mode memory.

SMAP makes kernel exploits that rely on reading or writing attacker-controlled user-mode data much more difficult. For example, if your exploit technique involves pointing a kernel structure at user-mode memory and having the kernel dereference it, SMAP will fault that read.

Together, SMEP and SMAP form a hardware boundary. SMEP: no executing user pages. SMAP: no accessing user memory without explicitly setting AC. Combined they close off a large category of exploitation primitives that relied on the kernel freely accessing user-mode memory.

---

## PTE Overwrites: The Dominant Kernel Exploitation Technique

For several years, PTE manipulation was the go-to kernel exploitation technique. You had arbitrary read/write in the kernel, so you used it to find and corrupt PTEs, turning pages from non-executable to executable, or flipping U/S bits for SMEP bypass. Connor McGarr wrote the definitive post on this.

The full PTE overwrite technique, putting it all together:

**Step 1: Get kernel base address.**

Options include:
- `NtQuerySystemInformation(SystemModuleInformation)` from medium integrity (before lockdown)
- Side-channel techniques
- Other info leaks specific to the vulnerability being exploited

**Step 2: Find MiGetPteAddress.**

With the kernel base and symbols (from public PDB files, downloadable from Microsoft's symbol server), calculate the offset to `MiGetPteAddress`. Something like:

```c
PVOID pMiGetPteAddress = (PBYTE)ntoskrnlBase + offset_MiGetPteAddress;
```

**Step 3: Leak the PTE base.**

```c
// MiGetPteAddress looks like:
// 48 C1 E9 09   shr rcx, 9
// 48 B8 ??   ?? ?? ?? ?? ?? ?? ??   mov rax, PTE_BASE  <-- this is at +0x13
// 48 03 C1      add rax, rcx
// C3            ret

ULONG64 pteBase = *(PULONG64)((PBYTE)pMiGetPteAddress + 0x13);
```

**Step 4: Calculate PTE address for your shellcode page.**

```c
ULONG64 pteAddress = ((shellcodeVA >> 9) & 0x7FFFFFFFF8) + pteBase;
```

**Step 5: Read the current PTE value.**

```c
ULONG64 currentPte = KernelArbitraryRead(pteAddress);
```

**Step 6: Modify the PTE.**

To make the page kernel-executable (clear NX, clear U/S):
```c
ULONG64 newPte = currentPte & ~(0x8000000000000000ULL); // clear NX bit (bit 63)
newPte &= ~(1ULL << 2); // clear U/S bit (bit 2) for SMEP bypass
KernelArbitraryWrite(pteAddress, newPte);
```

**Step 7: Execute shellcode.**

Redirect kernel execution to the shellcode address. The page is now marked as supervisor-accessible and executable. SMEP won't fire (U/S=0), NX won't fire (bit 63=0). Shellcode executes at ring 0.

<img src="/assets/media/windows-mitigations/pte-base-leak.png" alt="Exploit output: leaking MiGetPteAddress+0x13 to get the PTE base and calculating the PTE for a shellcode page" style="max-width:100%;border-radius:6px;margin:1.5em auto;display:block;border:none">

<img src="/assets/media/windows-mitigations/pte-wpte-output.png" alt="WinDbg !pte output showing PXE, PPE, PDE and PTE addresses for a virtual address" style="max-width:100%;border-radius:6px;margin:1.5em auto;display:block;border:none">

<img src="/assets/media/windows-mitigations/pte-manipulation.gif" alt="Animated: PTE bit manipulation flipping the NX and U/S bits to make a page kernel-executable" style="max-width:100%;border-radius:6px;margin:1.5em auto;display:block;border:none">

### Why HVCI Kills This

HVCI breaks step 6 at the hardware level. Even after you write the modified PTE, the physical page behind that virtual address is still governed by its Extended Page Table Entry (EPTE), which is controlled by the hypervisor running in VTL1. The EPTE for kernel data pages is set to R/W but not executable. The hypervisor never allows that physical page to become executable.

When the CPU tries to execute code from your shellcode page after the PTE manipulation, it checks both the PTE (which you modified to say "executable") AND the EPTE (which the hypervisor controls and says "not executable"). The EPTE wins. Access violation. The technique is dead on HVCI-enabled systems.

---

## CFG, kCFG, and XFG: Closing the Forward-Edge Problem

Control Flow Guard addresses a different attack surface: indirect function calls. The classic exploitation primitive after getting an arbitrary write is to overwrite a function pointer stored in a kernel object or vtable. Redirect that function pointer to your shellcode or the start of a ROP chain, wait for the kernel to call it, profit.

CFG works by maintaining a bitmap. Every valid indirect call target in the program gets a bit set in this bitmap. Before any indirect call (call through a function pointer or virtual dispatch), the compiler inserts code that checks whether the target address has its bit set in the bitmap. If not, the program terminates or invokes an error handler.

For user mode, this looks like:

```asm
; Compiler-generated CFG check before an indirect call:
mov  rcx, target_address
call  __guard_check_icall_ptr  ; checks if target_address is in the bitmap
; then the actual indirect call
call  target_address
```

The bitmap coverage: for user-mode processes, all DLLs and EXEs compiled with `/guard:cf` contribute their valid call targets to a shared bitmap. The bitmap is sized for the entire address space: 1 bit per 8 bytes, so for a 2GB (32-bit) address space that's 32MB, manageable. For 64-bit the full theoretical bitmap would be huge, so Windows uses a compressed representation for the full range.

### kCFG: The Kernel Side

kCFG arrived in Windows 10 1703. The concept is the same as user-mode CFG but for the kernel. The important difference: kCFG is only *effective* when VBS is enabled.

Here's why. The CFG bitmap for the kernel is itself stored in kernel memory. Without VBS, any attacker who has an arbitrary write in the kernel can modify the bitmap directly. Add an entry for your shellcode's address, and kCFG happily allows the indirect call. The bitmap becomes worthless.

With VBS enabled, the bitmap is protected by HVCI. An attacker with a kernel arbitrary write can't modify HVCI-protected memory. The bitmap integrity is guaranteed by the hypervisor. This is why kCFG and VBS are inseparable for effective forward-edge protection.

One additional note: kCFG also validates upper address bits regardless of VBS status. If a function pointer's upper bits look like a user-mode address (bit 47 = 0, so canonical user form), kCFG rejects it even without checking the bitmap. This prevents the simplest function pointer overwrite to user-mode shellcode regardless of VBS.

### XFG: Beyond the Bitmap

XFG (Xtended Flow Guard) was presented by David Weston at BlueHat Shanghai 2019. Regular CFG has a fundamental weakness: it only checks whether the target is a *valid function start*, not whether it's the *right type of function*. If you have two functions with the same CFG bitmap entry (both are valid function starts), you can substitute one for the other and CFG won't complain. This matters because attackers can find CFG-valid function addresses that are interesting for exploitation.

XFG embeds a 55-bit hash of the function's prototype (argument types, calling convention, return type) at the call site. The hash is placed 8 bytes above the actual call instruction. When the indirect call happens, the CPU (with XFG hardware support) or the compiler-inserted code computes whether the hash at the call site matches the hash of the target function. A type mismatch aborts the call.

The implication: even if you find a CFG-valid function pointer to substitute, it needs to have the same prototype hash as the expected target. This massively reduces the available gadget set.

XFG isn't universally deployed yet, but it represents the direction that forward-edge CFI is heading.

---

## ACG: Arbitrary Code Guard

Arbitrary Code Guard prevents processes from creating or modifying executable memory at all. VirtualProtect to executable fails. VirtualAlloc with PAGE_EXECUTE_READWRITE fails. WriteProcessMemory into executable memory fails. Even JIT compilers are blocked.

This is enforced per-process and controlled by `NtSetProcessInformation` with `ProcessDynamicCodePolicy`. It's opt-in for now but Chrome, Edge, and Windows Defender use it for certain processes.

ACG essentially brings HVCI's "no new executable code" property to user mode. In a process with ACG enabled, the only executable code is what was mapped during the process's initial loading (from signed PE files). No new executable pages can be created dynamically.

The impact on user-mode exploitation is severe. The classic post-CFG bypass path of "find a CFG-valid function pointer, overwrite it, call VirtualProtect to make a page executable, execute shellcode" fails at the VirtualProtect step. ACG blocks the VirtualProtect call.

User-mode attackers running against ACG processes need data-only attacks, gadgets from existing executable sections, or cross-process exploitation from a non-ACG process. For kernel exploits, ACG in user mode is irrelevant since you're already in the kernel. But for browser exploitation chains that start in a renderer process, ACG is a serious barrier.

---

## VBS and HVCI: When the Hypervisor Became Your Adversary

This is where the story gets genuinely interesting. Everything up to this point was OS-level protection that an attacker with kernel execution could bypass by modifying kernel data structures. SMEP? Flip a PTE. kASLR? Read MiGetPteAddress. DEP in kernel? Use NonPagedPoolNx bypass or pool grooming to get execution somewhere else. All these mitigations live in the same trust domain as an attacker who already owns the kernel.

VBS changes the trust model entirely.

Virtualization-Based Security uses Hyper-V to split the Windows system into two Virtual Trust Levels (VTLs). VTL0 is where the normal Windows kernel runs. VTL1 is the Secure Kernel, isolated, more privileged, and inaccessible from VTL0 no matter how completely VTL0 is compromised.

The VTL architecture looks like this:

```
+--------------------------------------------------+
|  VTL 1 (Secure World)                           |
|  Secure Kernel (SK)                             |
|  IUM processes (Isolated User Mode)             |
+--------------------------------------------------+
        |  Secure hypercall interface  |
+--------------------------------------------------+
|  Hypervisor (Hyper-V)                           |
|  Manages EPTs for both VTLs                     |
|  Arbitrates VTL transitions                     |
+--------------------------------------------------+
        |                             |
+------------------+   +--------------+
| VTL 0 (Normal)  |   | VTL 1 (Secure)|
| NT Kernel       |   | Secure Kernel |
| User processes  |   | IUM processes |
+------------------+   +--------------+
```

<img src="/assets/media/windows-mitigations/ept-gpa-to-spa.png" alt="VMCS and Extended Page Table Pointer (EPTP) converting Guest Physical Address to System Physical Address via EPT walk" style="max-width:100%;border-radius:6px;margin:1.5em auto;display:block;border:none">

The key hardware mechanism: Second Level Address Translation (SLAT). On Intel this is Extended Page Tables (EPT). The hypervisor maintains SLAT tables for each VTL. These EPTs operate below the regular Windows page tables. When the CPU translates a virtual address:

1. First, the VTL0 page tables translate VA to what they think is a physical address (actually a "Guest Physical Address" or GPA)
2. Then the EPT translates the GPA to a real physical address (Host Physical Address or HPA)

The hypervisor controls the EPTs. VTL0 cannot modify them. This is the foundation of HVCI.

### HVCI: Hypervisor-Protected Code Integrity

HVCI enforces that all kernel-mode pages are either readable/writable OR executable, but never both simultaneously. This is enforced at the EPT level, meaning even if VTL0 corrupts PTEs to say a page is RWX, the EPT overrides it.

How does this work in practice?

When ntoskrnl.exe loads a new driver (via `NtLoadDriver`), it validates the driver signature (Windows Driver Signature Enforcement), sets up PTEs, and calls the Secure Kernel to set up the corresponding EPTE. The hypercall is `HvCallModifyVtlProtectionMask` (hypercall number 0xC). The SK validates the request, checks the code integrity policy, and sets the EPTE to executable but non-writable.

For the driver's data sections and pool memory, the EPTE is set to writable but non-executable. These EPTEs are immutable from VTL0. Even with a kernel arbitrary write, you cannot modify them.

The result: all executable kernel pages came from properly signed PE files. All writeable kernel pages are non-executable. The W+X (write XOR execute) guarantee holds at the hardware level.

Trying to execute code from a modified data page:

1. Attacker corrupts a PTE to clear the NX bit for a data page
2. PTE says: executable
3. EPT says: non-executable
4. CPU checks EPT (which is "lower" and enforced by hardware): non-executable wins
5. Access violation

The PTE manipulation technique is dead. This is the HVCI guarantee.

### MBEC: Mode-Based Execution Control

There's still a gap. EPT needs to allow user-mode pages to be executable because legitimate user processes run code. DEP handles preventing kernel code from executing user pages (via the U/S PTE bit + SMEP), but EPT doesn't distinguish between execution contexts. The hypervisor marking a user-mode code page as executable in EPT means it's executable from both user mode AND kernel mode.

This creates an attack path: take a user-mode page with your shellcode, use an arbitrary write to clear the U/S bit in the PTE (making it look like a supervisor page), and now SMEP won't fire when the kernel jumps to it, and HVCI won't stop it because the EPTE already allows execution (for user-mode).

MBEC (Mode-Based Execution Control) closes this gap. It's an Intel hardware feature (available since Skylake) that adds an `ExecuteForUserMode` bit to EPT entries. When MBEC is enabled:

- EPT entries have separate "user mode executable" and "kernel mode executable" bits
- User-mode pages: `ExecuteForUserMode=1`, but kernel execution bit = 0
- Kernel code pages: kernel executable = 1, `ExecuteForUserMode=0`
- Kernel cannot execute user-mode pages regardless of PTE tricks

For CPUs without MBEC hardware support, Microsoft implemented RUM (Restricted User Mode). Instead of a hardware bit, the hypervisor maintains two separate EPT sets. When transitioning into the kernel (privilege level change from ring 3 to ring 0), the hypervisor switches EPT sets to one where user-mode pages have the execute bit cleared. When returning to user mode, it switches back. This costs performance but provides the same security guarantee.

Together, HVCI + MBEC/RUM create an environment where:
- You cannot execute data pages in the kernel (HVCI)
- You cannot execute user-mode pages in the kernel (MBEC/RUM)
- Unsigned drivers cannot load (kernel code integrity)

Classic shellcode execution in the kernel is completely dead on a fully HVCI-enabled system.

---

## Data-Only Attacks: What's Left When Shellcode Dies

HVCI kills shellcode execution but it doesn't prevent arbitrary writes to kernel data. Memory corruption vulnerabilities can still corrupt kernel objects. The question becomes: what can you do with an arbitrary write if you can't execute new code?

### Token Stealing: The Classic Data-Only Attack

The simplest and most reliable data-only attack is token stealing. Every process has an `_EPROCESS` structure in the kernel. That structure contains a `Token` field that points to the security token governing the process's privileges.

The attack:

1. Find the `_EPROCESS` structure for the SYSTEM process (which has a fully privileged token)
2. Read the `Token` field from the SYSTEM `_EPROCESS`
3. Find the `_EPROCESS` structure for your process
4. Write the SYSTEM token value into your process's `Token` field
5. Your process now has SYSTEM privileges

No code execution required. Pure data manipulation. HVCI allows this because you're writing to writable kernel data, not trying to execute anything.

The `_EPROCESS` for SYSTEM (PID 4) can be found by walking the process list starting from the kernel's `PsInitialSystemProcess` exported symbol. ASLR makes the address dynamic, but once you have any kernel address leak and an arbitrary read, walking the list is straightforward.

Token stealing has worked for a long time and continues to work on HVCI systems. It's the goto privilege escalation primitive for local kernel exploits that have arbitrary read/write but can't execute code.

### Calling Arbitrary Kernel APIs via ROP on Suspended Thread Stacks

Token stealing gets you privilege escalation, but sometimes you want to call arbitrary kernel APIs. For example, to unload a driver, restart a service, or interact with other kernel objects. If you can't write shellcode, can you still call arbitrary kernel functions?

Connor McGarr documented a technique in his HVCI exploitation post: use a suspended thread's kernel stack.

Every thread has a kernel stack. When a thread is blocked waiting for something, its kernel stack contains a ROP-like sequence of return addresses representing the call chain that blocked it. When the thread gets unblocked, those return addresses get used as the execution resumes.

The technique:

1. Find a target thread and suspend it
2. Get the kernel address of the thread's `KTHREAD` structure via `NtQuerySystemInformation` with class 5 (SystemProcessInformation), which leaks `KTHREAD` pointers
3. From the `KTHREAD`, find `StackBase` (the top of the kernel stack, typically at a well-known offset like `0x30`)
4. Use an arbitrary write to craft a ROP chain at the top of the kernel stack:
   - Return address pointing to the first gadget
   - Arguments and gadget data following it
5. Modify the thread's saved RSP (`KTHREAD.TrapFrame.Rsp` or similar) to point to your crafted ROP chain
6. Resume the thread
7. The thread resumes, pops your ROP chain, and executes arbitrary kernel-mode gadgets

Since you're using gadgets from existing executable kernel memory, HVCI doesn't fire. Since ROP uses `RET` instructions rather than indirect calls, kCFG doesn't check them. The technique works on fully HVCI+kCFG-enabled systems.

The result: you can call any kernel-mode function from your ROP chain. `NtQueryVirtualMemory`, `PsLookupProcessByProcessId`, `NtAllocateVirtualMemory`, whatever you need. Full kernel API access without executing a single byte of your own code.

This technique's expiration date is CET. When kernel-mode shadow stacks become mainstream, the return addresses on the kernel stack are protected. Corrupting the stack's return addresses triggers a shadow stack mismatch fault. The technique stops working.

---

## The Windows Kernel Pool: Grooming for Fun and Profit

Kernel pool exploitation is its own discipline. When you have a heap overflow in the kernel, you need to control what objects are adjacent in memory. Putting your controlled spray objects next to vulnerable pool allocations is called grooming, and it's significantly more complex in modern Windows.

Starting with Windows 10 19H1, the kernel uses the Segment Heap architecture instead of the old buddy allocator. The Segment Heap has three allocation strategies:

**kLFH (Lookaside-Free Handle, or just the Low Fragmentation Heap):**
- Handles small, fixed-size allocations
- Allocations are bucketed into size classes
- Each bucket has its own free list
- Here's the catch: kLFH doesn't activate for a bucket until at least 16 consecutive allocations of the same size have been made
- This matters for exploitation: you need to spray 16+ same-size objects before the heap will use the kLFH for that size, making adjacency predictable

**VS Segment (Variable Size):**
- Handles varied-size allocations
- Uses 8-byte headers before each allocation
- Can coalesce adjacent free chunks
- More fragmented and harder to predict than kLFH

**Large Alloc:**
- For allocations above a threshold
- Gets its own mapped region
- Not useful for traditional overflow-to-adjacent-object techniques

The old pool header `_POOL_HEADER` still exists for compatibility but means less than it used to for exploitation. Overwriting a pool header isn't the primitive it once was.

### What Makes a Good Pool Grooming Object?

For pool grooming to work, your spray objects need to satisfy these constraints:

**Same size**: The overflow needs to reach exactly your spray object. kLFH buckets are size-class based. If your vulnerable allocation is size 0x200, your spray objects need to be in the same 0x200 bucket.

**Same pool type**: Paged pool and nonpaged pool are separate. An overflow in paged pool can't reach nonpaged pool objects. You need spray objects in the same pool type as the vulnerable allocation.

**Allocatable from user mode**: Since you're sending the allocations from user mode, the object needs to be triggerable via a user-mode syscall. Good candidates include: pipe buffers (via `CreatePipe`), event objects (via `NtCreateEvent`), token objects, section objects, and objects allocated via `NtAllocateLocallyUniqueId` with crafted parameters.

**Contains interesting members**: The goal is to overwrite something useful. Common targets: function pointers (pre-CFG era), size fields (turn a bounded read into an unbounded one), pointer fields (turn a struct member into an arbitrary read/write), or object manager headers.

The modern kernel pool exploitation workflow:

1. Identify the vulnerable object's size and pool type from reverse engineering
2. Find user-controllable kernel allocations of the same size and pool type
3. Spray to fill free slots in that size class (may need 16+ for kLFH to kick in)
4. Trigger the vulnerable allocation to land in a kLFH bucket adjacent to spray objects
5. Trigger the overflow to overwrite a critical field in an adjacent spray object
6. Use the corrupted object as a read/write primitive
7. Escalate from limited primitive to full arbitrary read/write

Grooming is never guaranteed. Modern kernel allocators have enough randomness that you're often working with probabilities. High-reliability kernel exploits spend significant effort on reliable grooming, using multiple rounds of allocations and free operations to shape the heap into a predictable layout.

---

## ALPC: The IPC Primitive That Unlocks Kernel R/W

Advanced Local Procedure Call (ALPC) is Windows' internal IPC mechanism, replacing the older LPC. It's the backbone of Windows interprocess communication: RPC uses ALPC for all local calls, processes communicate with csrss.exe via ALPC on startup, Windows Error Reporting uses it, and dozens of other system components depend on it. ALPC is ubiquitous.

For exploit researchers, ALPC is interesting for two reasons: (1) it's a rich attack surface since messages sent from user mode to system ALPC ports cross the privilege boundary, and (2) ALPC objects in kernel pool are exploitable primitives.

### The ALPC Object Model

The core ALPC kernel object is `_ALPC_PORT`:

```c
struct _ALPC_PORT {
    LIST_ENTRY PortListEntry;           // 0x00
    _ALPC_COMMUNICATION_INFO* CommunicationInfo; // 0x10
    _EPROCESS* OwnerProcess;            // 0x18
    _KQUEUE* CompletionPort;            // 0x20
    // ... (0x1D8 bytes total)
    _ALPC_PORT* TargetQueuePort;        // 0x1A8
    _ALPC_PORT* TargetSequencePort;     // 0x1B0
    _KALPC_MESSAGE* CachedMessage;      // 0x1B8
    // ...
};
```

<img src="/assets/media/windows-mitigations/alpc-port-structure.png" alt="_ALPC_PORT kernel object structure showing CommunicationInfo, OwnerProcess, and CachedMessage fields" style="max-width:100%;border-radius:6px;margin:1.5em auto;display:block;border:none">

An ALPC connection involves multiple port types: server connection ports, server communication ports, and client communication ports. The setup flow: server calls `NtAlpcCreatePort` to create a named server port, client calls `NtAlpcConnectPort` to connect, server accepts with `NtAlpcAcceptConnectPort`. After that, both sides communicate via `NtAlpcSendWaitReceivePort`.

Messages use `_PORT_MESSAGE` as a header:

```c
struct _PORT_MESSAGE {
    SHORT DataLength;    // 0x00
    SHORT TotalLength;   // 0x02
    SHORT Type;          // 0x04
    SHORT DataInfoOffset; // 0x06
    CLIENT_ID ClientId;  // 0x08
    ULONG MessageId;     // 0x18
    ULONG64 ClientViewSize; // 0x20
};
```

### ALPC Message Transfer

ALPC supports two message transfer methods. The default is the double-buffer mechanism: the kernel copies data from the sender's buffer into a kernel-mode `_KALPC_MESSAGE` allocation, then copies it again into the receiver's buffer. Maximum message size via this method is 64KB (enforced by `AlpcMaxAllowedMessageLength`).

The section mechanism uses a shared memory section. The sender creates an ALPC section via `NtAlpcCreatePortSection`, maps a view, writes data into the view, and sends the section handle as an attribute with the message. The receiver maps its own view of the same section. No kernel copy needed. This path is used for large messages and is significantly more efficient.

### Exploitation: The ExtensionBuffer Write Primitive

The 2026 y3a technique builds a full unlimited kernel arbitrary read/write from almost any paged pool vulnerability that hits an ALPC object. The key structures are `_KALPC_MESSAGE` and `_KALPC_RESERVE`.

The `_KALPC_RESERVE` object is a pre-allocated message slot. It has a pointer to a `_KALPC_MESSAGE`. The `_KALPC_MESSAGE` has an `ExtensionBuffer` pointer and `ExtensionBufferSize` field. These are used for extra message attributes.

The exploit technique:

1. Use a pool vulnerability to corrupt an adjacent `_KALPC_RESERVE` or `_KALPC_MESSAGE` in the paged pool
2. Overwrite the `ExtensionBuffer` pointer with an arbitrary kernel address
3. Send a message that uses the extension buffer
4. The kernel writes message attribute data to your controlled `ExtensionBuffer` address
5. That's your arbitrary write primitive

For arbitrary read, combine this with `NtAlpcQueryInformation` with info class `0xC` (AlpcConnectedSIDInformation or similar). This returns an `OwnerProcess` pointer from the `_ALPC_PORT` structure, which you can use to validate your read primitives and calculate offsets for further exploitation.

The handle table technique gives you unlimited read/write instead of a single write:

1. Corrupt an ALPC object's reference count or size field via your initial primitive
2. Use this to allocate another ALPC object at a controlled kernel address
3. Build a fake port object with controlled `ExtensionBuffer` and `ExtensionBufferSize`
4. Each send operation through this fake port writes to a different address
5. Chain sends to write arbitrary data to arbitrary kernel addresses

This turns almost any paged pool adjacent object vulnerability into full unlimited kernel R/W. No code execution needed at this stage. You build your read/write primitive on top of pool corruption and ALPC.

<img src="/assets/media/windows-mitigations/alpc-write-chain.png" alt="ALPC ExtensionBuffer write primitive chain: pool corruption to arbitrary kernel write via _KALPC_MESSAGE" style="max-width:100%;border-radius:6px;margin:1.5em auto;display:block;border:none">

---

## CET and Shadow Stacks: The Hardware Nail in ROP's Coffin

Intel CET (Control-flow Enforcement Technology) has been available in processors since Tiger Lake (2020) and is the hardware response to both ROP and JOP (Jump-Oriented Programming). CET has two components: Indirect Branch Tracking (IBT) and Shadow Stacks. Windows uses Shadow Stacks but not IBT (CFG handles that purpose in Windows).

### How Shadow Stacks Work

A shadow stack is a separate hardware-managed stack stored in protected memory. It is NOT the regular stack. It lives at a separate address, is managed by the CPU, and can only be modified by specific privileged instructions.

The shadow stack interaction with function calls and returns:

```
CALL instruction:
  1. Push return address onto regular stack (RSP)
  2. Push return address onto shadow stack (SSP, shadow stack pointer)
  3. Jump to target

RET instruction:
  1. Pop return address from regular stack into RIP
  2. Pop return address from shadow stack
  3. COMPARE: regular RIP vs shadow stack value
  4. If mismatch: #CP (Control Protection fault)
  5. If match: continue execution
```

The shadow stack is accessible only via privileged instructions (`RSTORSSP`, `SAVEPREVSSP`, `CLRSSBSY`, `INCSSP`). Normal read/write memory instructions cannot modify shadow stack memory. The CPU's shadow stack pages have special protection in their page table attributes.

This breaks ROP at the fundamental level. A ROP chain works by overwriting return addresses on the regular stack. When the function returns, the CPU reads your modified return address from the regular stack. With CET enabled, it also checks the shadow stack. The shadow stack contains the legitimate return address (the one that was pushed when the function was called). Your modified address doesn't match. Fault.

### kCET: Kernel Shadow Stacks

User-mode shadow stacks require Tiger Lake hardware. Kernel-mode shadow stacks (kCET) landed in Windows as an optional feature, toggled via "Kernel-mode Hardware-enforced Stack Protection" in Windows Security Center.

The kernel implementation is complex because:

1. Each processor needs its own kernel shadow stack (one per logical CPU)
2. Each thread needs its own shadow stack (or at minimum, state saved/restored on context switch)
3. The shadow stacks themselves need to be allocated in protected memory

The Secure Kernel is involved. Setting up per-processor shadow stacks requires hypercalls into VTL1. The SK allocates and configures the shadow stack pages with appropriate EPTE protection (non-writable, shadow-stack marked). VTL0 cannot modify these EPTEs.

Connor McGarr's kernel shadow stacks post goes into the full implementation detail, including how the Windows kernel handles the VMCS fields for shadow stack pointers, how the Secure Kernel coordinates shadow stack setup, and how exceptions are handled with shadow stacks active.

### Impact on the Suspended Thread ROP Technique

Remember the data-only exploitation technique using suspended thread kernel stacks? kCET kills it directly. When you corrupt a thread's saved kernel stack return addresses, the shadow stack still contains the original return addresses. When the thread resumes and hits the first RET instruction, the CPU compares the modified return address (from your corrupted regular stack) against the original return address (from the shadow stack). Mismatch. #CP fault. System crash or process termination.

Once kCET becomes mainstream on enterprise hardware, the suspended thread ROP technique for HVCI exploitation stops working. At that point, the only viable exploitation primitives in a fully hardened environment are pure data-only: token stealing, `_EPROCESS` manipulation, registry modifications via kernel write, and similar.

---

## BYOVD: Why Sophisticated Actors Stopped Writing Kernel Exploits

Here's the thing. All that mitigation depth above? Real research, real work, real bypasses for the right context. But if you're a ransomware operator in 2026, you don't do any of it. You use BYOVD.

Bring Your Own Vulnerable Driver is conceptually simple: you have administrator access (which you get via phishing, stolen credentials, initial access brokers, whatever), you drop a legitimately signed Windows driver that has a known memory corruption vulnerability, you load it via `sc create` and `sc start`, and you send it IOCTL requests that exploit its own vulnerability. The driver runs the kernel operations for you. You bypass every single mitigation in this post simultaneously because you aren't exploiting anything in the OS. You're just using a trusted kernel module's own bug against it.

### The Scale of Modern BYOVD

The numbers from ESET's March 2026 report are worth sitting with:

- 90 unique EDR killer tools identified in active use
- 54 of those 54 use BYOVD as their underlying mechanism
- 35 distinct vulnerable drivers being collectively abused across those tools
- Multiple ransomware operations sharing the same BYOVD tooling

EDRKillShifter, originally tied to the RansomHub ransomware group, is now shared tooling across at least eight different groups: Qilin, Medusa, Blacksuit, and others. The kernel bypass capability has become a commodity. Groups don't need their own researchers; they rent or steal the capability from each other.

Bitdefender's threat intelligence predicts BYOVD will reach 75% prevalence in enterprise ransomware attacks. This isn't a niche technique. It's the standard operating procedure.

### How the EDR Kill Actually Works

The technical mechanism: Windows EDRs register callbacks with the kernel to get notified of security-relevant events. These notifications use kernel callback registration APIs:

- `PsSetCreateProcessNotifyRoutine()`: notified when processes are created or terminated
- `PsSetCreateThreadNotifyRoutine()`: notified on thread creation/termination
- `PsSetLoadImageNotifyRoutine()`: notified when PE images are loaded (DLLs, EXEs)
- `CmRegisterCallback()`: registry operation notifications
- Minifilter file system callbacks for file read/write monitoring

An EDR that can't see process creation events is blind. An EDR that can't see file writes can't block malicious file drops. These callbacks are the EDR's eyes.

The vulnerable driver provides access to kernel memory or kernel objects. Using that access, the BYOVD tool:

1. Locates the callback array for `PsSetCreateProcessNotifyRoutine` by scanning for the kernel pattern or using symbol information
2. Zeroes out the callback entries for the EDR's driver
3. Repeats for other callback arrays
4. Optionally, terminates the EDR process directly by abusing Process Object kernel handles

For step 4: some vulnerable drivers expose process handle creation at a kernel level, bypassing Protected Process Light. PPL is supposed to prevent SYSTEM-level code from killing security processes. A kernel-level handle with PROCESS_TERMINATE access obtained via the vulnerable driver completely bypasses PPL.

### The Driver Blocklist Game

Microsoft maintains the Vulnerable Driver Blocklist, enforced by HVCI: a deny-list of known malicious or vulnerable drivers identified by hash, file name, and signing certificate. Reasonable in theory. Completely undermined in practice by the economics of the problem.

**The 8-byte TrueSight.sys problem**: Checkpoint Research documented that one specific vulnerable driver (TrueSight.sys v2.0.2 from Antiy Labs) has been used to generate over 2,500 unique variants. Attackers modify exactly 8 bytes in the PE header (non-functional padding bytes), producing a binary with a completely different SHA-256 hash. The digital signature remains valid because code signing signatures use a hash of specific signed content, not the entire file verbatim. Each variant sails past the blocklist's hash check. The file name can be changed too, defeating that check. Only the certificate-based block is effective, but even that gets circumvented.

**The expired certificate problem**: Huntress documented a case where a driver signed in 2006 with an expired and revoked certificate loaded successfully in 2026. Windows honors trusted timestamps from before the certificate expiry. If a driver was timestamped in 2006 when the certificate was valid, that timestamp proves the signature was valid at that time. Additionally, legacy cross-signed drivers from before Microsoft's 2015 policy change have a grandfather exception baked into the boot loading policy. The combination means old signed drivers with expired and revoked certificates can still load on modern Windows.

**The update lag problem**: The blocklist is a reactive tool. A new BYOVD driver gets added only after it's discovered in active campaigns and Microsoft processes the report. The lag between first use and blocklist update is measured in weeks to months. During that window, the driver is fully usable.

### HVCI as the Real Defense

HVCI with its driver enforcement is the strongest available defense against BYOVD. HVCI enforces the blocklist during driver loading and also prevents any kernel code that wasn't loaded before HVCI initialization from executing. If the blocklist blocks a driver, HVCI prevents it from loading.

But HVCI has real-world limitations:

**Hardware requirements**: HVCI requires specific hardware capabilities including IOMMU/DMAR, firmware support, and in some configurations MBEC. Many enterprise machines, especially those more than a few years old, don't meet these requirements.

**The admin bypass**: An attacker who already has admin access can disable HVCI by modifying the BCD (Boot Configuration Data) and rebooting. This requires admin and a reboot, both of which may be detectable, but it's not cryptographically impossible.

**Audit mode**: HVCI can be deployed in audit mode (logging violations without blocking them) for compatibility testing. Some organizations leave it in audit mode permanently because blocking mode breaks something. Audit mode provides no protection against BYOVD.

**The still-loading-successfully problem**: Even with HVCI and the blocklist, if the driver isn't on the blocklist yet (new variant, freshly discovered vulnerability), it loads fine.

---

## BYOI: When You Don't Even Need a Driver

A related technique from the other direction: BYOI (Bring Your Own Interpreter). Instead of a vulnerable kernel driver, you bring a legitimate trusted runtime with good reputation and no driver-related blocklist rules.

g3tsyst3m documented this comprehensively. The runtimes involved: LuaJIT, Julia, Node.js, Deno, and Bun. All of these are signed binaries with established reputation, downloaded directly from their official sources.

### How BYOI Works

The technique doesn't target the kernel at all. It's about executing shellcode in user mode while evading EDR detection.

The flow for a LuaJIT-based example:

1. Drop `luajit.exe` (signed by the LuaJIT project, good reputation) alongside a `.lua` script
2. The Lua script uses LuaJIT's FFI (Foreign Function Interface) to call Windows APIs directly
3. FFI calls: `VirtualAllocExNuma` to allocate executable memory, `RtlMoveMemory` or similar to write shellcode
4. Use `EnumUILanguagesW` as the shellcode trigger: pass a callback pointer pointing to your shellcode

```lua
local ffi = require("ffi")
ffi.cdef[[
    void* VirtualAllocExNuma(void* hProcess, void* lpAddress, size_t dwSize, 
                             uint32_t flAllocationType, uint32_t flProtect, 
                             uint32_t nndPreferred);
    bool EnumUILanguagesW(void* lpUILanguageEnumProc, uint32_t dwFlags, 
                          uint64_t lParam);
]]
local shellcode = "\xfc\x48\x83\xe4..." -- your shellcode bytes
local mem = ffi.C.VirtualAllocExNuma(
    ffi.cast("void*", -1), nil, #shellcode, 0x3000, 0x40, 0
)
ffi.copy(mem, shellcode, #shellcode)
ffi.C.EnumUILanguagesW(mem, 0, 0)
```

`VirtualAllocExNuma` is the allocation function. Some EDRs hook `VirtualAlloc` and `VirtualAllocEx` but miss `VirtualAllocExNuma`, the NUMA-aware variant. The shellcode allocation happens without triggering the hooked paths.

`EnumUILanguagesW` as the execution trigger: this is a legitimate Windows API for enumerating installed UI languages. It takes a callback function pointer. You pass your shellcode address as the callback. When `EnumUILanguagesW` calls back into "your code", the callstack trace shows:
- `EnumUILanguagesW` (kernel32.dll)
- `EnumUILanguagesWWorker` (kernel32.dll)
- Your shellcode (called by Microsoft's API)

EDRs that look at callstack depth and callstack legitimacy see Microsoft's API as the caller. No injection API. No cross-process operation. No PE loader. The execution looks legitimate.

<img src="/assets/media/windows-mitigations/byoi-callstack.png" alt="BYOI callstack showing EnumUILanguagesW as the caller of shellcode - legitimate API chain with no injection telemetry" style="max-width:100%;border-radius:6px;margin:1.5em auto;display:block;border:none">

### Why BYOI Evades Detection

The specific EDR detection categories that BYOI avoids:

**No PE loader activity**: Classic DLL injection involves `LoadLibrary`, `WriteProcessMemory`, and thread creation. BYOI uses none of these. The interpreter loads itself normally. The shellcode never appears as a PE.

**No injection API patterns**: `CreateRemoteThread`, `NtCreateThreadEx`, `RtlCreateUserThread`, `APC injection`... none of these appear in the callstack or API trace.

**No cross-process operations**: Everything happens in the interpreter's own process. No other process is modified.

**Script content not surfaced**: Most EDR configurations don't scan Lua or JavaScript file content for shellcode signatures. Even if they scan for malicious PowerShell or Python, Lua scripts may be in a blind spot.

**Binary reputation**: The interpreter binary itself has excellent reputation. It was downloaded from the official source, signed by a trusted authority. Reputation-based controls don't flag it.

The implication for defenders: threat intelligence based on "known bad binaries" and "known bad injection patterns" misses this category entirely. BYOI requires behavioral detection of what the interpreted code is doing, which is significantly harder.

---

## VBS Enclaves: Attacking the Secure Kernel

<img src="/assets/media/windows-mitigations/vbs-enclave-architecture.png" alt="VBS Enclave architecture: VTL0 (Kernel + User Mode) and VTL1 (Secure Kernel + Isolated User Mode) over Hypervisor and Hardware" style="max-width:85%;border-radius:6px;margin:1.5em auto;display:block;border:none">

The most recent frontier: VBS enclaves. Microsoft added support for third-party enclaves running in Isolated User Mode (IUM), which is the user-mode component of VTL1. These enclaves are DLLs signed via Azure Artifact Signing. They load inside a normal VTL0 host process, but execute in a VTL1 isolated address space.

The trust model:
- Host process (VTL0) cannot read or write enclave memory
- Enclave can read and write VTL0 host process memory
- Even full kernel compromise (VTL0) cannot access enclave memory
- The only way into an enclave is via the defined `CallEnclave` interface

<img src="/assets/media/windows-mitigations/sfape-smartscreen.png" alt="Windows Security Center showing Enhanced Phishing Protection powered by SFAPE inside a VBS enclave" style="max-width:80%;border-radius:6px;margin:1.5em auto;display:block;border:none">

Microsoft ships several enclaves internally:
- `sfape.dll` (SmartScreen's Enhanced Phishing Protection): handles password hashing in VTL1
- Windows Search enclave
- Recall enclave

The logic: even if an attacker fully compromises VTL0 (kernel, driver, everything), sensitive operations happening inside IUM enclaves remain protected.

### The SFAPE Vulnerability

Doyensec's October 2026 research found and exploited a vulnerability in SFAPE that led to arbitrary code execution inside VTL1. This is significant: compromising the Secure Kernel from VTL0 is the crown jewel of Windows kernel exploitation right now.

**The root bug**: `SFAPE.dll`'s `Initialize` function. When called a second time (after initialization has already completed), the function writes the value `STATUS_ALREADY_INITIALIZED` (0xC0000510) to an attacker-controlled address. This is a fixed four-byte write of a known constant value.

The attacker controls the destination address. This is a small but reliable primitive: write exactly `0xC0000510` to any VTL1 address accessible from the VTL0 host's `CallEnclave` arguments.

**Step 2: Corrupting IsInsideEnclave**. SFAPE caches its own enclave base address in `g_enclaveBase`. `IsInsideEnclave(addr)` checks whether `addr` is within `[g_enclaveBase, g_enclaveBase + enclaveSize]`. By targeting the high DWORD of `g_enclaveBase` with the fixed write, the range validator is corrupted. `g_enclaveBase` now has an incorrect high DWORD (specifically the value `0xC0000510` written there).

**Step 3: Unlocking the TOCTOU bug**. SFAPE's `ClipboardInput` handler has a Time-of-Check Time-of-Use (TOCTOU) bug. The check (`IsInsideEnclave`) happened before the corruption. After the corruption, the check passes for addresses that shouldn't be inside the enclave. The vulnerable handler now accepts VTL0 host-controlled addresses as if they're enclave memory.

**Step 4: memset-to-zero primitive**. The TOCTOU combined with the corrupted range validator gives a `memset`-based zero-writing primitive over attacker-controlled VTL1 memory ranges.

**Step 5: CC-map pivot for read/write**. With a memset-to-zero primitive, carefully zero out specific bits in VTL1 structures to create a CC-map pivot (a creative data structure manipulation). This provides a `read16` (read 16 bytes from VTL1) and `write64` (write 64 bytes to VTL1) primitive.

**Step 6: VertValidTargetTable overwrite**. VTL1 uses `vertdll.dll` to validate `CallEnclave` targets. `VertValidTargetTable` lists the valid enclave entry points. Use the read/write primitive to overwrite this table with an attacker-controlled address.

**Step 7: VTL1 code execution**. `NtContinue` can be used to transition into VTL1 and resume execution at a controlled EIP. With the `VertValidTargetTable` overwritten, you can now call arbitrary VTL1 addresses via `CallEnclave`. Full VTL1 code execution achieved.

The patch came in September 2026 as KB5124008.

### Offensive Uses of VBS Enclaves

The offensive security angle isn't just about exploiting enclaves. It's about using them.

**Outflank's sleep mask**: EDRs perform memory scanning during the sleep periods of C2 implants (looking for characteristic memory patterns). An implant running inside a VTL1 enclave can decommit itself from VTL0 memory during sleep, run entirely within VTL1, and have no VTL0-visible memory footprint during the scan. The EDR's memory scanner operates in VTL0 and cannot see into VTL1.

**Mirage by Ori David (Akamai)**: Store payload data inside a VBS enclave. The payload bytes live in VTL1 memory where EDR memory inspection (which works from VTL0) cannot reach them. Retrieve the payload at execution time via the controlled enclave interface.

The pattern: VTL1 is a safe zone that EDR operating in VTL0 cannot introspect. If you have legitimate access to create an enclave (which requires the right enclave DLL signed via Azure Artifact Signing), you have an execution and storage environment that's invisible to VTL0-based monitoring.

---

## Putting the Attack Chains Together: What Real Exploitation Looks Like

Now that we've covered every component, let me connect them into actual exploitation scenarios.

### The Full Modern Kernel Exploit Chain (2024, No HVCI)

A realistic chain on a system with ASLR, SMEP, kCFG, but no HVCI or CET:

1. **Info leak #1**: Use `NtQuerySystemInformation(SystemModuleInformation)` from medium integrity to get ntoskrnl base. If that's locked down, use the pool vulnerability itself to leak a kernel address.

2. **Info leak #2**: Use arbitrary kernel read to read `*(MiGetPteAddress + 0x13)` for the PTE base.

3. **Exploitation**: Trigger pool corruption (use-after-free, type confusion, out-of-bounds write) to overwrite an adjacent object in a precisely groomed heap layout.

4. **Primitive building**: Turn the initial overwrite into an arbitrary read/write. Options include corrupting an ALPC object for the ExtensionBuffer technique, corrupting a pipe buffer size for an over-read, or other object-specific tricks.

5. **PTE manipulation**: Find the PTE for user-mode shellcode, clear U/S and NX bits. The shellcode page now looks like a supervisor-executable page.

6. **SMEP bypass**: The U/S bit flip handles SMEP. No need to touch CR4.

7. **kCFG bypass**: Find a valid kCFG function pointer (a function whose address is in the bitmap) that you can overwrite to redirect execution. Or just overwrite a pointer that bypasses kCFG checking (a callback registered via a mechanism that doesn't use `__guard_dispatch_icall`).

8. **Code execution**: Trigger the corrupted function pointer. Control flow reaches your PTE-manipulated page. Shellcode runs.

9. **Privilege escalation**: Token steal, then spawn a privileged child process.

This chain requires:
- An info leak vulnerability (or finding one that leaks addresses natively)
- A memory corruption vulnerability with cross-object overwrite capability
- Two paging structure manipulation steps
- One CFG bypass step

That's a lot. But there have been multiple CVEs in recent years that enabled all of this.

### The HVCI-Compliant Chain (2025+)

Same system but with HVCI on (no CET yet):

Steps 1-4 are the same (info leak, primitive building).

5. **PTE manipulation**: Still works to find the PTE. The write to the PTE executes fine. The page just won't execute (EPTE overrides).

6. **Change approach**: Instead of PTE to executable, use the arbitrary write for a data-only attack.

7. **Token stealing or suspended thread ROP**: Either overwrite the token pointer directly, or craft a ROP chain on a suspended thread's kernel stack using `KTHREAD.StackBase`.

8. **Kernel API calling via ROP**: The suspended thread ROP chain calls `PsLookupProcessByProcessId`, `ObReferenceObjectByPointer`, and other APIs to perform privileged operations without executable shellcode.

9. **Privilege escalation**: Token manipulation completes, privilege escalated.

kCFG still doesn't stop this because we used `RET`-based ROP, not indirect calls.

### The Full HVCI + kCET Chain (2026+)

With both HVCI and kCET enabled:

Steps 1-4: same.

5-7: Token stealing still works. Arbitrary data writes to kernel structures still work.

But the suspended thread ROP technique is dead. kCET means corrupting the kernel stack return addresses triggers #CP.

What's left: pure data manipulation. Token stealing. Direct `_EPROCESS` member modification. `_TOKEN` privilege field manipulation. These don't involve code execution or return address corruption.

The practical impact: on a fully hardened system (HVCI + kCET), kernel exploitation produces exactly one useful primitive: modify kernel data structures. You can still escalate privileges via token stealing. You can disable security features that live in writable kernel memory. But calling arbitrary kernel APIs requires finding other paths (legitimate APIs, interaction with ALPC servers, etc.).

---

## The Threat Intelligence Reality: What's Actually Being Used

All of that above is the technical depth. Here's the operational reality.

### BYOVD Dominates Enterprise Attacks

The numbers from ESET and Bitdefender's 2026 reports:

- 54 of 90 (60%) EDR killer tools use BYOVD
- RansomHub, Qilin, Medusa, Blacksuit all use the same BYOVD infrastructure
- EDRKillShifter shared tooling with C2 protocol variations
- Average time between new variant release and blocklist coverage: weeks

The threat model BYOVD exploits: attackers get admin access from phishing or credential theft (which they will keep doing). Admin access allows service creation. Service creation allows driver loading. The entire kernel mitigation stack becomes irrelevant because you're a trusted kernel module.

### The Certificate Ecosystem Problem

The legitimate driver signing ecosystem is the real vulnerability here. Attackers have discovered several reliable categories of drivers with kernel arbitrary write or arbitrary read:

**Legitimate hardware/software vendor drivers** with memory mapping features (IOCTL to map physical memory, read/write arbitrary physical addresses).

**Old AV/security drivers** with direct kernel object access and no modern security hardening.

**Hardware diagnostic drivers** from motherboard and GPU manufacturers with direct hardware I/O access.

The challenge: these drivers are legitimately signed by legitimate companies. Revoking the certificates causes problems for the legitimate users. Adding them to the blocklist requires Microsoft to identify them and take action. The turnaround time is long enough that multiple attack campaigns can run successfully in the gap.

### Where the Real Mitigations Matter

Where does the kernel mitigation stack actually matter in 2026?

**Browser sandbox escapes**: A sandboxed renderer process (Chrome, Firefox, Edge) needs to escape the sandbox to compromise the OS. Browser sandboxes run at low integrity with restricted APIs. They can't call `NtQuerySystemInformation` for kernel addresses, can't load arbitrary drivers, can't create services. These processes face the full mitigation stack with no shortcuts. A sandbox escape chain against a fully patched modern browser needs a true kernel vulnerability exploitation chain. This is where DEP, ASLR, SMEP, HVCI, and kCFG all matter simultaneously.

**Zero-day kernel exploit chains**: Nation-state groups and sophisticated threat actors develop kernel exploit chains against zero-day vulnerabilities. These chains burn fast once discovered but justify the investment. They face the full mitigation stack. An 0-day kernel exploit that worked in 2022 might need significant retooling for HVCI systems.

**Post-compromise privilege escalation without admin**: An attacker who gains code execution as a standard user (via browser exploit, document exploit) but hasn't achieved admin access yet faces the full mitigation stack. They can't use BYOVD without admin. They need a true kernel vulnerability.

---

## ALPC as an Attack Surface: The Deeper Picture

Beyond using ALPC objects as pool exploitation primitives, ALPC is worth understanding as an attack surface in its own right.

ALPC is used for virtually all internal Windows IPC. The Attack surface: when user-mode code sends ALPC messages to system ALPC servers (like the WER service, the Session Manager, Windows Defender's IPC interface), those messages cross the privilege boundary. Even if the ALPC core implementation is secure, any logic bug in a system component's message handling could be exploitable.

The y3a 2023 blog on ALPC workings covers the full object model:

**Port types**:
- Server connection port (named, public)
- Server communication port (per-client, created on connection)
- Client communication port (client's side)
- Unconnected communication port

**Attribute system**: ALPC's main advantage over LPC is secure handle transfer and view sharing. The `ALPC_HANDLE_ATTR` and `ALPC_DATA_VIEW_ATTR` attributes let you pass kernel handles and shared memory views between processes in a controlled way. The kernel validates these at ALPC level rather than trusting user-mode data.

**Security mode**: The section mechanism with `ALPC_VIEWFLG_SECURED` limits a section to two views maximum (server and one client), protecting shared memory from other processes.

The completions mechanisms for asynchronous ALPC are also worth knowing: completion lists (MDL-backed, efficient memory sharing), IO completion ports (documented, flexible), and kernel callbacks (for kernel mode only). Different components use different completion mechanisms, and the interaction between them is an area where logic bugs can appear.

---

## Windows Security Architecture: The Bigger Picture

Looking at all of this together, there's a clear architectural evolution.

**Era 1 (Windows XP - Vista): The Wild West**
Stack-based shellcode, hardcoded addresses, basic stack cookies. Any overflow -> shellcode. Single-primitive exploits everywhere.

**Era 2 (Vista - 8): Defense in Depth Basics**
DEP forced ROP. ASLR forced info leaks. Two primitives became standard requirement.

**Era 3 (8 - 10 1607): Kernel Hardening Begins**
NonPagedPoolNx, kASLR, SMEP. PTE manipulation emerged as the dominant bypass technique.

**Era 4 (10 1607 - 2004): CFG and VBS Arrive**
CFG and kCFG closed forward-edge overwrites (mostly). PTE base randomized. HVCI began deployment. PTE manipulation killed on HVCI systems.

**Era 5 (2004+): Data-Only Era**
HVCI mainstream on new hardware. CET arriving. BYOVD dominant. Data-only kernel attacks are the only viable path on fully hardened systems.

**Era 6 (kCET mainstream - future)**: Even kernel ROP via suspended threads stops working. Pure data manipulation only. Attackers fully move to BYOVD for privileged kernel ops.

The hardware/software co-design is worth appreciating. Each era's bypasses got patched by pulling in more hardware features. SMEP bypass via CR4 flip -> HyperGuard. SMEP bypass via PTE flip -> HVCI + MBEC. Kernel ROP for HVCI bypass -> kCET. Each iteration closed the previous bypass.

---

## Write-What-Where: Building From a Weak Primitive

A "write-what-where" is probably the most common initial primitive you get from a kernel memory corruption bug. You have an integer overflow in a size field, and that size field controls how far a copy goes. Or you have a type confusion that lets you write 8 bytes at an arbitrary kernel address. Or a use-after-free that lets you control a freed object's contents.

Write-what-where means: I can write an arbitrary QWORD (or DWORD) of my choice to an arbitrary kernel address.

This sounds powerful and it is, but it's not immediately obvious how to escalate it to meaningful code execution or privilege escalation. The classic primitive chains from Connor McGarr's write-what-where post illuminate the patterns.

### Overwriting `HalDispatchTable+0x8`

The old classic. The Hardware Abstraction Layer Dispatch Table (`HalDispatchTable`) is an array of function pointers in the kernel. `HalDispatchTable[1]` (at `HalDispatchTable + 0x8`) is called by `NtQueryIntervalProfile`, a user-callable API.

The exploit chain:

1. Find the address of `HalDispatchTable` via kASLR bypass (kernel symbol lookup from the PDB)
2. Write your shellcode address (or the address of your ROP chain pivot) to `HalDispatchTable + 0x8`
3. Call `NtQueryIntervalProfile` from user mode
4. The kernel calls `HalDispatchTable[1]`, which now points to your code

This was the go-to primitive in the Windows 7/8 era. CFG doesn't apply here because the HalDispatchTable calls happen through a table lookup, not through a CFG-checked indirect call instruction. Well, until things evolved.

The technique still works in some contexts even today, specifically on systems where kCFG is not fully enforced. But on modern systems with VBS/kCFG, the bitmap check catches the overwritten function pointer. HalDispatchTable entries are not in the CFG bitmap for user-mode addresses.

### Overwriting PreviousMode

A sneaky technique that doesn't require code execution at all: overwrite the `PreviousMode` field in the current thread's `ETHREAD` structure.

`PreviousMode` is a single byte in `ETHREAD` that indicates whether the previous privilege mode was kernel (0) or user (1). The kernel checks this field in many security-sensitive operations to decide whether to validate user-supplied pointer arguments or trust them directly.

If you overwrite `PreviousMode` from 1 (user) to 0 (kernel):

- Calls to `ZwReadVirtualMemory` and `ZwWriteVirtualMemory` no longer probe user buffers for accessibility
- The kernel trusts your pointers as kernel pointers
- You can read and write arbitrary kernel memory using documented NT APIs
- No arbitrary read primitive needed, no PTE calculation

The write is: find the offset of `PreviousMode` in `ETHREAD`, which is well-documented in public symbols. Calculate the address of your thread's `ETHREAD + offset_PreviousMode`. Write 0x00 there with your write primitive.

Then use `NtReadVirtualMemory` and `NtWriteVirtualMemory` to read/write arbitrary kernel memory. The APIs won't validate your "user mode" pointers anymore since you appear to be a kernel caller.

Then restore `PreviousMode` to 1 when done (to avoid crashing the system when the kernel tries to copy results back to user mode and validates the wrong thing).

### Overwriting `_SEP_TOKEN_PRIVILEGES`

Another pure data-only approach that doesn't even need code execution: direct token privilege manipulation.

The `_TOKEN` structure has a `_SEP_TOKEN_PRIVILEGES` member with three fields: `Present`, `Enabled`, and `EnabledByDefault`. Each bit in these 64-bit values corresponds to a privilege (like `SeDebugPrivilege`, `SeLoadDriverPrivilege`, etc.).

If you have arbitrary kernel write, find your process's `_EPROCESS`, find the `Token` field, dereference to get the `_TOKEN`, and then overwrite `Enabled` and `Present` with `0xFFFFFFFFFFFFFFFF`. Every privilege enabled. Including `SeDebugPrivilege` (read/write any process memory), `SeLoadDriverPrivilege` (load unsigned drivers without WHQL bypass), `SeTcbPrivilege` (act as part of the OS), and many others.

This doesn't require escalating to SYSTEM. It doesn't even require changing the token pointer. You just flip the privilege bits in your existing token.

---

## WinDbg: Reading Kernel Structures

One of the best ways to actually understand paging and kernel structures is to look at them live in WinDbg with a kernel debug session. Here's what that actually looks like for some of the concepts above.

### Reading a PTE in WinDbg

If you have a virtual address and want to inspect its PTE in WinDbg:

```
kd> !pte 0xffff800000000000
                                           VA ffff800000000000
PXE at FFFF94C7E3F1FFF8    PPE at FFFF94C7E3FFF000    PDE at FFFF94C7FFE00000    PTE at FFFF94FFFC000000
contains 00A0000001405063  contains 00A000000D4A1063  contains 00A000003E011063  contains 0000000000000000
pfn 1405      ---DA--KWEV   pfn d4a1      ---DA--KWEV   pfn 3e011     ---DA--KWEV   LARGE PAGE pfn 0
```

The `!pte` command shows you all four levels. The column headers show the addresses of the page table entries themselves (`PXE at`, `PPE at`, `PDE at`, `PTE at`). The `contains` row shows the actual entry values. The decoded flags tell you: `K` = kernel mode, `W` = writable, `E` = executable, `D` = dirty, `A` = accessed.

### Walking the Process List

Finding all processes in WinDbg:

```
kd> !process 0 0
PROCESS ffff8b01ec4e0080
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001aa000  ObjectTable: ffffb98c8b400740  HandleCount:  2538.
    Image: System

PROCESS ffff8b01f6020080
    ...
```

To read a specific EPROCESS field, like the token:

```
kd> dt nt!_EPROCESS ffff8b01ec4e0080 Token
   +0x4b8 Token : _EX_FAST_REF

kd> !token -n fffff8014c5e3060
_TOKEN ffff8b01f4a1c060
Flags: 0x2000
...
Privs: 00000000`ffffffff (enabled)
```

### Inspecting Pool Allocations

The `!pool` command shows pool metadata for a given address:

```
kd> !pool ffff8b01f8001000
Pool page ffff8b01f8001000 region is Nonpaged pool
 ffff8b01f8001000 size:  210 previous size:    0  (Allocated)  Irp 
 ffff8b01f8001210 size:   30 previous size:  210  (Allocated)  Irpq
```

The pool tag (`Irp`, `Irpq`) identifies which Windows component made the allocation. The pool allocator uses 4-byte ASCII tags for debugging. For exploitation, knowing the pool tag helps you identify which kernel objects land in which pool buckets and size classes.

Useful WinDbg commands for pool work:
- `!pool <addr>` to inspect metadata
- `!poolused` to dump pool usage statistics by tag
- `dt nt!_POOL_HEADER <addr>` to read the header struct

---

## The Kernel Exploit OPSEC Problem

There's a dimension to this whole thing that's worth talking about: detectability.

Even if a kernel exploit technically works, modern EDR and telemetry platforms are increasingly good at detecting exploitation behavior. Some indicators they watch for:

**Unusual NtQuerySystemInformation calls**: The info leak APIs that return kernel addresses leave telemetry. EDRs can correlate the timing: if a process calls `SystemModuleInformation` right before a known crash-causing IOCTL, that's a signal.

**Pool spray patterns**: Allocating thousands of objects of the same size in rapid succession is unusual behavior. Some EDRs track allocation rates and flag unusual patterns.

**Driver loading from unusual paths**: BYOVD involves loading a driver. `NtLoadDriver` from a temp directory, combined with a service created in the last 30 seconds, combined with the driver not being in the expected path, is a high-confidence indicator.

**Kernel callback deregistration**: If a process's notify callbacks disappear from the system callback arrays, that's detectable. Sysmon can't detect this directly (because it's a callback itself), but other monitoring frameworks and EDRs with custom minifilters can.

**Privilege token modifications**: ETW (Event Tracing for Windows) captures token manipulation events. `TokenElevation` changes are logged if you have the right audit policy.

**Shadow stack violations**: When kCET is on, #CP exceptions are auditable events. A process that generates multiple control protection faults before crashing is clearly trying to do ROP.

This is why sophisticated actors try to minimize their kernel exploit footprint. A BYOVD tool that runs for 2 seconds, kills callbacks, and exits leaves less telemetry than a kernel exploit chain that takes 30 seconds and makes hundreds of unusual syscalls.

---

## The Suspended Thread ROP Technique in Detail

Connor McGarr's HVCI post goes into the suspended thread technique in impressive depth. Let me elaborate on the full implementation because it's genuinely clever and understanding it shows exactly why kCET matters.

### What a Suspended Thread's Kernel Stack Looks Like

When a user-mode thread is blocked waiting (in `NtWaitForSingleObject`, for example), the thread's kernel execution is suspended at some point inside the kernel. The kernel stack at that point contains:

```
Higher addresses (top of kernel stack = KTHREAD.StackBase):
  ...
  Return address (back to whoever called the wait function)
  Saved registers
  Trap frame (the saved user-mode context)
  ...
  Return address to KiSystemCallReturn
  Return address within NtWaitForSingleObject
Lower addresses (current RSP):
```

The kernel stack grows downward (like all x86/x64 stacks). `KTHREAD.StackBase` points to the high end of the kernel stack. `KTHREAD.StackLimit` points to the low end.

When we craft a ROP chain on this stack, we're writing to addresses between `StackLimit` and `StackBase`, specifically near the top (near StackBase), since that's where the return addresses from the deepest call frames live.

### Finding KTHREAD via NtQuerySystemInformation

To know where a thread's kernel stack is, we need the `KTHREAD` address for that thread. The technique:

```c
// NtQuerySystemInformation class 5 = SystemProcessInformation
// Returns a list of all processes and their threads
// Each SYSTEM_THREAD_INFORMATION contains KernelStack

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION;
```

This doesn't directly give us the KTHREAD address. We need a different approach: use an arbitrary read to read the KTHREAD pointer from the kernel-mode thread data.

One approach: use the `NtQuerySystemInformation(SystemExtendedHandleInformation)` class, which in certain configurations leaks `ETHREAD` pointers. From the `ETHREAD`, the `KTHREAD` is embedded at offset 0 (they're the same structure, `_ETHREAD` starts with an embedded `_KTHREAD`).

Another approach: once you have any kernel address leak and an arbitrary read, walk the `KTHREAD` list from the well-known exported symbol `PsInitialSystemProcess`, find the target thread by TID or thread state, and extract its stack pointers.

### Reading KTHREAD.StackBase

```
kd> dt nt!_KTHREAD StackBase
   +0x030 StackBase : Ptr64 Void
```

The offset varies by build, but `StackBase` is well-documented in public symbols. With an arbitrary read and the KTHREAD address:

```c
PVOID stackBase = ArbitraryRead(kthreadAddress + KTHREAD_STACKBASE_OFFSET);
```

### Crafting the ROP Chain

The kernel stack at the suspended point looks like:

```
[StackBase - 0x8]:  Return address to KiSystemCallReturn
[StackBase - 0x10]: More return addresses
...
[current RSP]:      Current top of stack
```

We want to overwrite return addresses near the top with our ROP chain. The chain doesn't execute immediately; it executes when the thread's current blocking operation returns, unwinding the stack.

A simple ROP chain to call an arbitrary kernel function:

```
gadget: pop rcx; ret       <- load first argument
value:  desired_arg1

gadget: pop rdx; ret       <- load second argument  
value:  desired_arg2

gadget: pop r8; ret        <- load third argument
value:  desired_arg3

gadget: pop r9; ret        <- load fourth argument
value:  desired_arg4

gadget: sub rsp, 0x20; ret <- shadow space (required for Windows x64 calling convention)

target_function_address    <- the kernel function we want to call

gadget: ret                <- clean landing after function returns
```

After writing this chain to the stack using our arbitrary kernel write primitive, we modify the thread's saved RSP (in the `KTHREAD.TrapFrame` or the saved kernel stack pointer) to point to our ROP chain.

Then `ResumeThread`. The thread resumes kernel-mode execution, pops our ROP chain, and calls whatever kernel function we specified with our arguments.

### Why kCFG Doesn't Stop This

kCFG checks indirect function calls. Our ROP chain uses `RET` instructions, not indirect calls. The final target function call is actually a `RET` that jumps to the function address we placed on the stack. That `RET` doesn't go through the `__guard_dispatch_icall` stub that kCFG injects. kCFG is bypassed by design.

This is a fundamental limitation of CFI schemes that only protect forward edges (calls). Backward edge protection (returns) requires separate hardware support, which is exactly what CET shadow stacks provide.

### kCET Kills This

When kernel CET is enabled, every `RET` instruction compares the regular stack return address against the shadow stack return address. Our tampered return addresses on the regular stack don't match the original return addresses on the shadow stack. First mismatch: #CP fault. System.

This is why kCET deployment is a significant event for the state of kernel exploitation. The suspended thread technique is one of the best ways to call arbitrary kernel code on HVCI systems, and kCET removes it cleanly.

---

## Understanding ALPC Attributes: Handle Transfer and Section Views

The ALPC attribute system is worth understanding for anyone doing IPC security research or trying to understand what attack surface looks like across the privilege boundary.

When an ALPC message is sent, it can carry attributes that transfer kernel objects between processes:

**ALPC_HDLATTR (Handle Attribute)**: Transfers a kernel handle from sender to receiver. The receiver gets a handle in its own handle table pointing to the same kernel object. This is how processes can share file handles, event handles, and so on through ALPC. The kernel duplicates the handle securely, with access rights controlled by the attribute.

**ALPC_VIEWATTR (View Attribute)**: Shares a memory section view. The sender creates an ALPC section via `NtAlpcCreatePortSection`, maps a view, and attaches it to a message. The receiver gets a view of the same section. Memory reads from the receiver's view see the sender's writes. This is the efficient path for large data transfer.

The security model: the kernel validates these attributes at the ALPC level. You can't inject arbitrary handles. You can only transfer handles you own and that you have permission to duplicate. The view attribute system respects section permissions (read-only sections stay read-only even after transfer).

For attack research: the interesting cases are where system ALPC servers (running as SYSTEM or LSASS) accept messages from low-integrity processes and process those messages in ways that could be exploited. The core ALPC code is generally solid. The bugs tend to be in the message handlers built on top of it, where the server processes message content without sufficient validation.

---

## The EPT Deep Dive: What HVCI Actually Looks Like

Understanding HVCI requires understanding Extended Page Tables (EPT) at a deeper level. Let me walk through what the hypervisor actually manages.

EPTs are the hardware mechanism for second-level address translation. The CPU walking the VTL0 page tables produces a Guest Physical Address (GPA). The EPT translates that GPA to a Host Physical Address (HPA, the real DRAM address). This two-level translation is transparent to VTL0 code.

EPT entries have a structure similar to regular PTEs but different:

```
Bits 2-0: Read/Write/Execute access for supervisor (kernel) mode
Bit 10:   Execute access for user mode (the MBEC bit, ExecuteForUserMode)
Bits 51-12: Physical address of next level / final page
Bit 57-52: Available to hypervisor (used for tracking)
```

The key insight is that EPT access control is separate from PTE access control. The final effective permissions for a memory access are the intersection of both:

- EPT says Writable, PTE says Read-Only: the page is read-only (most restrictive wins)
- EPT says Non-Execute, PTE says Executable: the page is non-executable

HVCI configures EPTs so that:

**Kernel code pages** (ntoskrnl.exe, driver .text sections): EPT bits = executable, NOT writable.
**Kernel data pages** (nonpaged pool, driver data sections): EPT bits = writable, NOT executable.
**User code pages** (process .text sections): EPT bits = executable for user-mode, NOT executable for kernel-mode (the MBEC bit).
**User data pages** (stack, heap): EPT bits = writable, NOT executable.

The hypercall for modifying these protections is `HvCallModifyVtlProtectionMask` (0xC). VTL0 can call this via `vmcall` to request protection changes, but the Secure Kernel validates every request against its code integrity policy. If you're trying to make a data page executable or make a code page writable from VTL0, the SK rejects it.

The only way to get a new executable kernel page approved is to present a properly signed driver image. The SK checks the catalog signature or embedded signature, validates against the Windows Driver Signing Policy, and only then sets up an executable EPT mapping for that code.

### How HVCI Protects the kCFG Bitmap

The kCFG bitmap is a classic example of HVCI-protected data. Without VBS:
- kCFG bitmap is in kernel virtual memory (writable)
- Attacker with arbitrary kernel write corrupts the bitmap
- kCFG check passes for any address you add

With VBS and HVCI:
- The kCFG bitmap pages are set up with EPT marking them non-writable from VTL0
- VTL0 kernel code can read the bitmap but cannot write it
- The bitmap is initialized by the Secure Kernel when kCFG-enabled modules are loaded
- An attacker with arbitrary kernel write cannot modify those pages

The Secure Kernel updates the bitmap via protected operations during driver and module loading. VTL0 never has write access to the bitmap pages. This is what makes kCFG actually meaningful as a mitigation.

---

## The Segment Heap Deep Dive: Beating Modern Pool Allocations

The Windows kernel Segment Heap is significantly more complex than the old buddy allocator. Understanding it in detail is essential for reliable pool exploitation.

### kLFH Bucket Activation

The Low Fragmentation Heap (LFH) in the kernel uses bucket-based allocation. Each bucket serves a specific size range. kLFH doesn't activate for a bucket by default; activation happens when the allocator observes "enough" consecutive allocations in that bucket.

The activation threshold: Microsoft's internal documentation suggests 16 consecutive same-size allocations trigger LFH for that bucket. After activation:
- Allocations in that bucket are served from the LFH bucket exclusively
- Allocations are contiguous within a "LFH subsegment"
- Free slots within the same subsegment are served in FIFO order
- This creates predictable layout: allocate N objects, free every other one, then allocate the target object

Before triggering LFH for a bucket, allocations come from the VS (Variable Size) segment, which has much less predictable layout.

**Practical implication**: in a pool exploit, your grooming spray needs to trigger LFH activation for your target size bucket before your vulnerable allocation. This means:

```
// Rough pseudocode for pool grooming
spray_objects = []
// First, trigger kLFH activation for the target size class
for i in range(32):  // More than 16 to be safe
    spray_objects.append(allocate_target_size_object())

// Now free half to create holes
for i in range(0, 32, 2):
    free(spray_objects[i])

// Trigger the vulnerable allocation
// It should land in one of the holes we just created
trigger_vulnerable_alloc()

// Our vulnerable allocation is now adjacent to our spray objects
```

### The VS Segment and Header Corruption

For allocations that don't fit in kLFH buckets, the VS segment handles them. VS segment allocations have an 8-byte header:

```c
struct _HEAP_VS_CHUNK_HEADER {
    HEAP_VS_CHUNK_HEADER_SIZE sizes; // size info
    ULONG64 EncodedSegmentPageOffset : 16;
    ULONG64 UnusedBytes : 8;
    ULONG64 SkipDuringWalk : 1;
    ULONG64 Spare : 39;
};
```

The sizes field contains both the current chunk size and the previous chunk size. These are used by the allocator when coalescing free chunks. Corrupting these fields can cause the allocator to believe adjacent chunks are at different offsets, leading to controlled overlap or controlled writes when the corrupted chunk is freed.

Classic VS segment overflow technique:
1. Allocate object A (VS segment, some size)
2. Allocate object B immediately after A (same VS segment, same or similar size)
3. Overflow A's contents into B's VS header
4. Free B (triggers coalescing)
5. The corrupted size fields cause the coalescing to merge "wrong" chunks
6. Allocate new objects into the coalesced region, overlapping with existing objects

### Large Allocation Exploitation

Large allocations (above ~32KB) go to dedicated mapped regions. Each large allocation gets its own section. These are isolated from each other by design. Traditional overflow-to-adjacent-object attacks don't apply in the same way.

For large allocation exploitation, the approaches are different:
- Use the large allocation as a spray target when you have a dangling pointer (use-after-free)
- Use the large allocation itself as the initial overflowable object, corrupting metadata at the end of its mapped region
- Use timing attacks: free the large allocation at the right moment to get it freed and reallocated as a different object type (the kernel reuses mapped regions for new large allocations)

### Which Kernel Objects Work for Grooming?

The list of user-triggerable paged pool objects has grown and shrunk over time as Microsoft hardens things:

**Pipe buffers** (`CreateNamedPipe` + `CreateFile`): Allocates a paged pool buffer when you write to a pipe. The size is controlled by the write size. Pool type is paged. Easy to trigger from user mode. Historically one of the most reliable grooming objects.

**Event objects** (`NtCreateEvent`): Small objects (~0x40 bytes), paged pool. Very fast to allocate thousands of them.

**Mutex objects**: Similar to events, small and allocatable in bulk.

**Key objects** (`NtCreateKey`): Registry key objects in paged pool. Variable size based on key name length. Useful for specific size targets.

**_ALPC_PORT objects**: As discussed above. Allocatable via `NtAlpcCreatePort`. Interesting because they have pointer-sized members you can target.

**Token objects**: Not directly user-triggerable in bulk, but some techniques allow controlled token allocation.

For nonpaged pool grooming, the options are more limited since fewer user-triggerable operations allocate in nonpaged pool. Network-related allocations (NDIS buffers, TDI structures) sometimes work, but they require different triggering mechanisms.

---

## Token Integrity Levels and Sandboxing

Since we're covering the full picture, mandatory integrity control deserves mention. Windows labels all objects and processes with an integrity level: Untrusted (0x0000), Low (0x1000), Medium (0x2000), High (0x3000), System (0x4000), and Protected Process (0x5000+).

A process can only access objects at or below its own integrity level. The kernel enforces this through mandatory access checks layered on top of discretionary ACLs. This is why a sandboxed browser renderer (Low integrity) can't call `NtQuerySystemInformation` for kernel addresses (which requires Medium+). And why PPL processes require a process with matching or higher protection level to access.

For kernel exploitation: if you're starting from a sandboxed process (Low integrity), you have tighter constraints. Many of the info leak syscalls are blocked. Direct service creation is blocked. The BYOVD path requires Medium+ (and in practice, Admin). Token stealing via kernel exploit is still feasible, but you first need to find a path from Low integrity to get the kernel exploit opportunity at all.

The common pattern for browser-based full-chain exploits: browser remote code execution gives code execution in a low-integrity renderer process. Then a sandbox escape vulnerability (often in the kernel or a kernel-mode driver) escalates from low integrity to system. The kernel exploit chain needs to work from a low-integrity context, which further constrains the info leak options.

---

## Practical Defensive Guidance

What actually matters for defenders right now:

**Enable HVCI on all hardware that supports it.** This is the single highest-impact control against BYOVD and kernel exploitation. If you're buying hardware, buy hardware that supports HVCI with MBEC. Windows 11 on Secured Core PCs has this by default.

**Keep the Vulnerable Driver Blocklist updated and in block mode (not audit mode).** Audit mode provides no protection. Block mode catches the known bad drivers. Pair it with AppLocker or WDAC policies that only allow approved drivers to load.

**Monitor for unexpected service and driver creation.** A service being created to load a driver you don't recognize is a significant indicator. EDRs should alert on `NtLoadDriver` calls for non-approved drivers. The Windows event log has events for this (System Event ID 7045 for new service installs).

**PPL-protect your security tools.** Windows Defender and third-party EDRs should be running as Protected Process Light (PPL) at minimum. PPL prevents `OpenProcess` with `PROCESS_TERMINATE` access from non-PPL processes. Without PPL, an attacker with SYSTEM privileges can just kill the EDR process directly without needing any driver.

**Understand your attack surface.** If you're running legacy drivers (even legitimate vendor drivers) that expose physical memory mapping or kernel read/write via IOCTL, evaluate whether those need to be deployed. The BYOVD threat specifically targets legitimate but vulnerable drivers.

**Don't ignore BYOI.** If your EDR detection strategy relies on monitoring PE loader activity, injection APIs, and cross-process operations, you're blind to BYOI. Test your detection capabilities against LuaJIT and similar trusted-interpreter techniques. Consider script content inspection and behavioral monitoring of trusted runtimes.

---

## Where We Are: The State of Modern Windows Exploitation

The full picture:

A fully hardened Windows system (HVCI on, kCET on, CFG/kCFG on, up-to-date driver blocklist in block mode, MBEC supported hardware, PPL for security software) requires for successful exploitation:

1. An info leak to defeat ASLR
2. A memory corruption primitive
3. A technique that works under HVCI (data-only: token stealing, or other data manipulation)
4. kCFG compliance (data-only attacks inherently satisfy this)
5. A technique that survives kCET (pure data writes, not stack corruption)

That's genuinely expensive. Nation-state groups develop these chains. They cost hundreds of thousands of dollars in research, they burn fast, and they're not shared casually.

For everyone else? BYOVD. It costs a few thousand dollars for the tooling or less (since most of it is shared anyway), it scales to any organization, it bypasses the entire mitigation stack described above, and it has a fully commoditized ecosystem built up around it.

The gap between "theoretically hardened" and "practically protected" is exactly where BYOVD lives. And that gap exists because:
- Not all enterprise hardware supports HVCI
- Many organizations run HVCI in audit mode
- The driver signing ecosystem can't be revoked quickly
- Admin access is too easy to obtain via phishing/credentials

The interesting research frontier right now:
- Exploiting VTL1 itself or the Secure Kernel (like the SFAPE research)
- Understanding what data-only attacks look like after kCET removes ROP
- Building reliable pool exploitation primitives via ALPC objects against modern segment heap
- Enclaves as both attack and defense infrastructure

If you want to go deeper on any single piece of this, the reference reading list:

- [Connor McGarr's full exploit dev series](https://connormcgarr.github.io/) - the gold standard for technical depth on every topic covered here
- [y3a's ALPC exploit technique post](https://y3a.github.io/2026/11/25/alpc-exploit-technique/) - modern pool exploitation via ALPC objects
- [Doyensec's SFAPE research](https://blog.doyensec.com/2026/10/13/Sfape.html) - VTL1 code execution via enclave bug chains
- [g3tsyst3m's BYOI writeup](https://g3tsyst3m.com/byoi/Bring-Your-Own-Interpreter-EDR-Evasion-with-LuaJIT,-Julia,-Node.js,-Deno,-and-Bun/) - trusted interpreter EDR evasion
- [y3a's ALPC internals post](https://y3a.github.io/2023/07/25/alpc-workings/) - ALPC object model and IPC mechanics

The arms race continues. It always does.
