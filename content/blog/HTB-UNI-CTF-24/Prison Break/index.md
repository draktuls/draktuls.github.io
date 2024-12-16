---
title: "[Pwn][Medium] Prison Break"
description: "Older glibc UAF heap note"
date: 2024-12-16
summary: "Prison Break was a classic vanilla heap note challenge with `UAF` bug. I had to leak libc addresses off the heap to acquire `__free_hook` address which could then be overwritten to `system`."
tags: ["Hack The Box", "Exploit Development", "Pwn", "Reverse Engineering", "University CTF 2024", "Heap", "Free Hook", "Heap Grooming", "Use After Free"]
draft: false
slug: "prison-break"
---



