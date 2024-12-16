---
title: "[Pwn][Hard] Dead or Alive"
description: "UAF heap note without Copy operation on newer glibc"
date: "2024-12-16"
summary: "Dead or Alive was a hard Pwn challenge which composed of `UAF` bug in side a heap note. It was very similar to the Prison Break challenge, but without Copy operation. Glibc present was a newer one, therefore no hooks were present, and I resorted to `atexit` function handlers overwrite to achieve RCE."
tags: ["Hack The Box", "Exploit Development", "Pwn", "Reverse Engineering", "University CTF 2024", "Heap", "Heap Grooming", "Atexit RCE"]
draft: false
slug: "dead-or-alive"
---



test