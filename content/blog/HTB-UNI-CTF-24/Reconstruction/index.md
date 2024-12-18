---
title: "Reconstruction"
description: "Shellcode challenge"
date: "2024-12-16"
summary: "Reconstruction was very easy Pwn challenge, which contained a custom RWX region and arbitrary shellcode execution. This shellcode was allowed to only have certain bytes and the main purpose was to essentially set certain registers to exact values."
tags: ["Hack The Box", "Shellcode", "Pwn", "Reverse Engineering", "University CTF 2024"]
draft: false
slug: "reconstruction"
---

Difficulty: `very easy`

One of the Council's divine weapons has its components, known as registers, misaligned.
Can you restore them and revive this ancient weapon?

## Init

We are given custom `glibc` and the binary. This means we will need to reverse it.

## Reversing

We have a simple program which expects string `fix` as the first input. 

A mmap call is followed which creates RWX memory. We are given `read` syscall which will write into that region.

This input is then filtered with an array of bytes:
```c
{ 0x49, 0xc7, 0xb9, 0xc0, 0xde, 0x37, 0x13, 0xc4, 0xc6, 0xef, 0xbe, 0xad, 0xca, 0xfe, 0xc3, 0x00, 0xba, 0xbd }
```

At first I was looking through the x86 ISA to check for valid opcodes and possible payloads before actually finishing the reversing.
This was pretty silly as looking at the upcoming code would pretty much kill all other possible payloads.

As for the code which validated the correct execution:
```c
qVar2 = regs(buf[(int)(uint)i]);
if (qVar2 != (&values)[(int)(uint)i]) {
    qVar2 = (&values)[(int)(uint)i];
    uVar1 = regs(buf[(int)(uint)i]);
    printf("%s\n[-] Value of [ %s$%s%s ]: [ %s0x%lx%s ]%s\n\n[+] Correct value: [ %s0x%lx%s ]\n\n "
            ,&DAT_00102022,&DAT_0010335c,buf[(int)(uint)i],&DAT_00102022,&DAT_0010335c,uVar1,
            &DAT_00102022,&DAT_001033b9,&DAT_001033c1,qVar2,&DAT_001033b9);
    uVar1 = 0;
    goto LAB_00101b0e;
}
```

This essentially checks a value for certain register.

For example `r8` is expected to hold `0x1337C0DEh`.

Overall we need to match these registers:
```c
. . . . .
  cmp = strcmp(param_1,"r8");
  if ((((cmp != 0) && (cmp = strcmp(param_1,"r9"), in_R8 = in_R9, cmp != 0)) &&
      (cmp = strcmp(param_1,"r10"), in_R8 = in_R10, cmp != 0)) &&
     (((cmp = strcmp(param_1,"r12"), in_R8 = unaff_R12, cmp != 0 &&
       (cmp = strcmp(param_1,"r13"), in_R8 = unaff_R13, cmp != 0)) &&
      ((cmp = strcmp(param_1,"r14"), in_R8 = unaff_R14, cmp != 0 &&
       (cmp = strcmp(param_1,"r15"), in_R8 = unaff_R15, cmp != 0)))))) {
. . . . .
```

To these values:
```
    1337C0DEh,                 DEADBEEFh,                 DEAD1337h,                 1337CAFEh,
    BEEFC0DEh,                 13371337h,                 
    1337DEADh
```

Lastly if we have these values set we simply print the flag file.

## Shellcode

You can choose whatever assembler you wish, I used simple [online assembler](https://defuse.ca/online-x86-assembler.htm).

`mov` was one of the opcodes present inside the filtering array. Therefore I was certain that some moves would be possible.

I came up with this:
```asm
0:  49 c7 c0 de c0 37 13    mov    r8,0x1337c0de
7:  49 b9 ef be ad de 00    movabs r9,0xdeadbeef
e:  00 00 00
11: 49 ba 37 13 ad de 00    movabs r10,0xdead1337
18: 00 00 00
1b: 49 c7 c4 fe ca 37 13    mov    r12,0x1337cafe
22: 49 bd de c0 ef be 00    movabs r13,0xbeefc0de
29: 00 00 00
2c: 49 c7 c6 37 13 37 13    mov    r14,0x13371337
33: 49 c7 c7 ad de 37 13    mov    r15,0x1337dead
3a: c3                      ret 
```

In the end we use `ret` to return from the call, which is also correct byte.

I wasn't expecting a clean first iteration however this shellcode passes all the checks and is executed correctly:

```
[!] Carefully place all the components: HTB{r3c0n5trucT_d3m_r3g5_bcf86b71e0be5e512c1185a8faca0028}
```

## Attachment

- [Exploit script](dstr.py) - Can be done in oneliner, but I whatever
- [Challenge files](pwn_reconstruction.zip)
