---
title: Introducing Renef
author: ahmethan
date: 2026-02-27 12:00:00 +0300
categories: [Announcements]
tags: [renef, android, reverse-engineering, arm64]
pin: true
---

## What is Renef?

Renef is a dynamic instrumentation toolkit designed for Android ARM64 platforms. It allows you to hook, trace, and manipulate native and Java functions at runtime — without requiring ptrace.

Whether you're doing security research, reverse engineering, or solving CTF challenges, Renef gives you a powerful and flexible scripting interface powered by Lua 5.4.

## Core Features

- **Function Hooking**: Supports both PLT/GOT and inline trampoline hooks on ARM64
- **Lua Scripting**: Write instrumentation scripts with a Frida-like API
- **No ptrace**: Process injection via memfd + shellcode — no ptrace dependency
- **Memory Operations**: Scan, read, write, and patch memory with wildcard patterns
- **Java Hooking**: Hook Java methods through JNI integration
- **TUI Scanner**: Interactive terminal-based memory scanner

## Quick Example

Here's a simple Lua script that hooks a native function and logs its arguments:

```lua
local mod = Module.find("libtarget.so")

for _, sym in ipairs(Module.exports("libtarget.so")) do
    if sym.name == "secret_check" then
        hook("libtarget.so", sym.offset, {
            onEnter = function(args)
                print("secret_check called with: " .. tostring(args[0]))
            end,
            onLeave = function(retval)
                print("returned: " .. tostring(retval))
            end
        })
        break
    end
end
```

## What's Next?

This blog will cover topics like:
- Practical hooking tutorials
- SSL pinning and root detection bypass techniques
- Android internals and ARM64 architecture deep dives
- CTF writeups using Renef

Stay tuned for more posts. Check out the [documentation](https://renef.io) to get started.
