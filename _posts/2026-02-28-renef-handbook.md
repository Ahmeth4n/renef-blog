---
layout: post
title: "Renef Handbook: Dynamic Instrumentation Framework for Android"
date: 2026-02-28
categories: [android, security, reverse-engineering]
tags: [renef, android, arm64, hooking, dynamic-instrumentation, lua]
author: mehmetfarisacar
image: /assets/img/renef-handbook/renef_wallpaper.svg
---

![renef wallpaper](/assets/img/renef-handbook/renef_wallpaper.svg)

Renef is a framework designed to provide dynamic instrumentation at both the native and ART levels within the Android ARM64 runtime environment. The tool was developed to enable runtime hooking of native functions, perform memory search and patch operations, and intervene in Java methods executing on the ART runtime.

Renef's primary architectural distinction is that it does not rely on ptrace during the injection process. Instead, it adopts an in-memory shared object injection approach using an anonymous file descriptor created via memfd_create.

With this method, the payload is loaded directly into the target process's address space without ever being written to disk. The injected payload embeds a Lua 5.4–based scripting engine, through which hook, memory, and Java APIs are exposed and managed.

In this article, Renef's architecture, injection approach, and the operational principles of its hook engine will be examined from a technical perspective.

## Contents

1. [General Architecture](#1-general-architecture)
2. [Hook Engine](#2-hook-engine)
   - 2.1 [Trampoline Hooking](#21-trampoline-hooking)
   - 2.2 [PLT/GOT Hooking](#22-pltgot-hooking)
3. [Hook Execution Model](#3-hook-execution-model)
   - 3.1 [onEnter](#31-onenter)
   - 3.2 [onLeave](#32-onleave)
4. [Renef Lab Cases](#4-renef-lab-cases)
   - 4.1 [Native Layer](#41-native-layer)
     - 4.1.1 [String Return Hook](#411-string-return-hook)
     - 4.1.2 [Argument Hook](#412-argument-hook)
     - 4.1.3 [Memory Operations](#413-memory-operations)
     - 4.1.4 [Memory Patch](#414-memory-patch)
   - 4.2 [Java Hooking at the ART Level](#42-java-hooking-at-the-art-level)
     - 4.2.1 [Java Method Hook](#421-java-method-hook)
     - 4.2.2 [Static Method Hook](#422-static-method-hook)
5. [Conclusion](#5-conclusion)
6. [References and Additional Links](#6-references-and-additional-links)

---

## 1. General Architecture

Renef consists of three core components: the client, the server running on the Android side, and the payload injected into the target process.

The client component is a CLI application running on the host machine. It receives user commands, loads Lua scripts, and forwards them to the device via ADB. The client side does not contain analysis logic; it functions solely as a control and communication layer.

The server component runs on the Android device and manages the injection process. This layer is responsible for loading the payload into the target process and handling communication over an Abstract Unix Domain Socket.

The use of the abstract namespace instead of TCP is preferred to avoid creating socket artifacts on the filesystem and to minimize the network-exposed attack surface.

The payload component (libagent.so) is the shared object injected into the target process's address space. The Lua 5.4–based scripting engine operates within this layer.

The hook engine, memory operations, and Java interception APIs are implemented inside the payload. As a result, user-defined scripts are executed directly within the context of the target process.

This architectural separation decouples the control plane from the execution plane. While the client is responsible solely for command transmission, the actual instrumentation operations are performed within the target process itself.

## 2. Hook Engine

![Renef General Arch](/assets/img/renef-handbook/renef_hook_engine.svg)

One of Renef's core functional components is its hook engine. The framework supports two distinct hooking approaches for intercepting functions operating at the native layer:

- **trampoline**
- **pltgot**

### 2.1 Trampoline Hooking

Trampoline hooking is based on the inline hooking approach and is implemented using the Capstone disassembly engine. This method serves as the default hook type.

In the inline hooking model, the initial instructions at the entry point of the target function are read, disassembled, and safely copied to a separate memory region. Subsequently, a branch/jump instruction is written at the beginning of the function to redirect the execution flow to the hook handler.

### 2.2 PLT/GOT Hooking

The PLT/GOT-based hooking method operates on external symbols resolved by the dynamic linker. Instead of modifying the function's entry point directly, this approach alters the corresponding PLT (Procedure Linkage Table) or GOT (Global Offset Table) entry to which the call is resolved.

In dynamically linked function calls, the execution flow typically follows this pattern:

- The code branches to the corresponding PLT entry of the target function.
- Through the PLT, the real address is resolved via the GOT table.
- The GOT entry points to the actual function address.

In the PLT/GOT hooking approach, the call chain is altered by redirecting this GOT entry to a different address.

## 3. Hook Execution Model

In Renef, hook definitions are implemented through the Lua scripting layer. The hook API provides a callback-based interception model for both native functions and Java methods executing on the ART runtime.

The basic hook structure is as follows:

```lua

hook("libc.so", offset, {
    onEnter = function(args)
    end,
    onLeave = function(retval)
        return retval
    end
})

```

This model operates through two primary callbacks: onEnter and onLeave.

### 3.1 onEnter

The onEnter callback is triggered immediately before the target function or method is executed.

##### For native functions:

- Parameters are accessible through the args[] array.
- Indices such as args[0], args[1], etc., represent arguments passed via registers at call time.
- At this stage, parameters can be inspected or modified.

```lua

hook("libc.so", open_offset, {
    onEnter = function(args)
        local path = Memory.readString(args[0])
        if path then
            print("[open] " .. path)
        end
    end
})

```

In this example:

- args[0] represents the first parameter of the function.
- The actual string value is read from the pointer using Memory.readString().
- The parameter is therefore observed before the function is executed.

##### For Java methods:

- args[] is passed in accordance with the JNI calling convention.
- Method parameters are received as references.
- The execution of the original method can be prevented by setting args.skip = true.

For example, completely bypassing a Java method:

```lua

hook("com/example/security/PinChecker", "verify",
     "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V", {
    onEnter = function(args)
        args.skip = true
    end
})

```

In this hook definition, the expression provided as the third parameter ([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V represents the method's JNI signature.

The types inside the parentheses specify the parameter types (X509Certificate[] and String), while the V outside the parentheses indicates that the return type is void. Since args.skip = true is used, the method's bytecode is never executed and the call is directly bypassed.

### 3.2 onLeave

The onLeave callback is triggered at the moment the target function or method returns.

##### For native functions:

- The original return value is received through the retval parameter.
- The return value can be overridden by returning a new value.

For example:

```lua

hook("libtarget.so", 0x1234, {
    onLeave = function(retval)
        return 1234
    end
})

```

In this case, regardless of the function's actual return value, 1234 is passed back to the caller.

##### For Java methods:

- The return value is overridden using a type that matches the method signature.

For example, for a method that returns a boolean:

```lua

hook("com/example/security/Validator", "isValid",
     "(Ljava/lang/String;)Z", {
    onLeave = function(retval)
        return 1
    end
})

```

## 4. Renef Lab Cases

### 4.1 Native Layer

#### 4.1.1 String Return Hook

In this scenario, the objective is to manipulate the application's control flow by modifying a jstring value returned at the native layer during runtime.

On the application side, a native method named getLicenseKey() is invoked. If this method returns "GOLD_KEY", a flag encrypted with Base64 + XOR is decoded and displayed to the user.

By default, the native implementation returns "WRONG_KEY".

##### Application Flow

Control mechanism on the Java side:

```java

String key = getLicenseKey();
if (key.equals("GOLD_KEY")) {
    tvResult.setText(decodeFlag());
}

```

Native implementation:

```cpp

JNIEXPORT jstring JNICALL
Java_com_byteria_labrenef_Case01Activity_getLicenseKey(JNIEnv* env, jobject) {
    return env->NewStringUTF("WRONG_KEY");
}

```

##### Analysis Strategy

The approach followed in this scenario is as follows:

- Verify whether libchallenge01.so is loaded
- Identify the relevant exported symbol
- Override the return value as "GOLD_KEY" within onLeave

Since the function returns a string, Renef's JNI-aware return type format is used to ensure proper type handling.

```lua

return {__jni_type="string", value="..."}

```

##### Renef Lua Script

```lua

local lib = "libchallenge01.so"

print("Looking for " .. lib .. "...")

if not Module.find(lib) then
    print("[WARN] Not loaded!")
    return
end

local exports = Module.exports(lib)
if not exports or #exports == 0 then
    print("[ERROR] No exports")
    return
end

local func = exports[1]
print("Hooking: " .. func.name .. " @ 0x" .. string.format("%x", func.offset))

hook(lib, func.offset, {
    onEnter = function(args)
        print("[CALLED] getLicenseKey")
    end,
    onLeave = function(retval)
        print("[+] Returning GOLD_KEY")
        return {__jni_type="string", value="GOLD_KEY"}
    end
})

print("Hook installed!")

```

##### Script Explanation

###### Library Check

```lua
Module.find(lib)
```

Checks whether the relevant shared object is loaded in memory.

###### Export Enumeration

```lua
Module.exports(lib)
```

Lists the exported symbols within the library. In this example, the first export directly corresponds to the target function.

###### Hook Installation

```lua
hook(lib, func.offset, { ... })
```

The hook is installed using the export offset.

###### onEnter

```lua
onEnter = function(args)
```

The function call is observed. Since the parameter is not used in this case, it is only logged.

###### onLeave – Critical Point

```lua
return {__jni_type="string", value="GOLD_KEY"}
```

This line explicitly specifies the JNI return type and ensures that a new jstring is created. Even if the native implementation returns "WRONG_KEY", the Java layer receives "GOLD_KEY".

![Renef Lab Cases - String Return Hook](/assets/img/renef-handbook/string_return_hook.png)

The output above demonstrates that the script was successfully loaded via the Renef CLI and that the hook was installed correctly.

- The **spawn com.byteria.labrenef** command launches the target application and attaches to the process.
- The **l /data/local/tmp/case01.lua -w** command loads the Lua script and enables **watch** mode.
- The script searches for *libchallenge01.so*.
- The symbol *Java_com_byteria_labrenef_Case01Activity_getLicenseKey* is identified from the export table.
- The hook is installed using the offset (0x6a8).
- The *[CALLED] getLicenseKey* log line indicates that the function has been triggered.
- The *[+] Returning GOLD_KEY* log line confirms that the return value has been successfully overridden.

Thanks to watch mode (-w), hook invocations can be monitored in real time. The CLI session remains active, allowing immediate testing of any modifications made to the script.

#### 4.1.2 Argument Hook

In this scenario, the objective is to observe the argument passed to a validation function running at the native layer and manipulate the application flow by controlling the return value.

On the application side, the user enters a PIN, which is forwarded to the native method verifyPin(pin). If the validation succeeds at the native layer (result == 1), the application decrypts an AES-encrypted flag and displays it on the screen.

##### Application Flow

On the Java side, the PIN is retrieved and passed to the native method; if the return value is 1, the flag is decoded:

```java
int pin = txt.isEmpty() ? 0 : Integer.parseInt(txt);
int result = verifyPin(pin);
if (result == 1) {
    tvResult.setText(decodeFlag());
} else {
    tvResult.setText("result: " + result);
}
```

The native implementation performs the PIN validation:

```cpp
JNIEXPORT jint JNICALL
Java_com_byteria_labrenef_Case02Activity_verifyPin(JNIEnv*, jobject, jint pin) {
    return (pin == 9999) ? 1 : 0;
}
```

##### Analysis Strategy

The approach followed in this scenario is:

- Verify whether libchallenge02.so is loaded
- Identify the exported target function
- Log the pin argument inside onEnter
- Override the return value inside onLeave to bypass validation

The JNI function signature is structured as follows:

- JNIEnv* (arg0)
- jobject (arg1)
- jint pin (arg2)

Therefore, the pin value can be accessed via args[2].

##### Renef Lua Script

```lua

local lib = "libchallenge02.so"

print("Looking for " .. lib .. "...")

if not Module.find(lib) then
    print("[WARN] Not loaded!")
    return
end

local exports = Module.exports(lib)
if not exports or #exports == 0 then
    print("[ERROR] No exports")
    return
end

local func = exports[1]
print("Hooking: " .. func.name .. " @ 0x" .. string.format("%x", func.offset))

hook(lib, func.offset, {
    onEnter = function(args)
        print("[CALLED] pin: " .. args[2])
    end,
    onLeave = function(retval)
        print("Original result: " .. retval)
        return 1
    end
})

print("Hook installed!")

```

#### Script Explanation

```lua
onEnter = function(args)
    print("[CALLED] pin: " .. args[2])
end
```

Here, args[2] corresponds to the jint pin parameter. This allows the entered PIN to be observed at runtime, regardless of the value provided by the user.

```lua
onLeave = function(retval)
    return 1
end
```

- The native function normally returns 0 unless pin == 9999.
- However, by returning 1 inside onLeave, the Java-side validation always succeeds.

![Renef Lab Cases - Argument Hook](/assets/img/renef-handbook/argument_hook.png)

The output above demonstrates that, in the Argument Hook scenario, both argument observation and return value manipulation were successfully performed.

- The unhook all command removes all previously installed hooks. This step is used to clean the runtime environment before switching to a new scenario.
- The Removed 2 hook(s) line indicates that two active hooks were detached.
- The l /data/local/tmp/case02.lua -w command loads the new Lua script and enables watch mode.
- The Looking for libchallenge02.so... line shows that the target library is being searched in memory.
- The Hooking: Java_com_byteria_labrenef_Case02Activity_verifyPin @ 0x610 line confirms that the hook was installed using the offset of the exported JNI function.

When the hook is triggered:

- [CALLED] pin: 0 → The user-provided PIN value is observed at runtime.
- Original result: 0 → The native function's actual return value is logged.

When a different PIN is entered:

- [CALLED] pin: 55
- Original result: 0

In both cases, the native function returns 0.

#### 4.1.3 Memory Operations

In this scenario, the objective is to read data stored in memory at the native layer during runtime. The goal is not to modify the function's return value directly, but to analyze a buffer created in memory through a hook.

This case demonstrates the capabilities of Renef's Memory API.

##### Application Flow

On the Java side, when the button is pressed, the following native method is invoked:

```java

public native String getMemoryTarget();

```

Native implementation:

```cpp

static const unsigned char ENC_KEY[] = {
    0x12, 0x72, 0x02, 0x13, 0x72, 0x15, 0x6C, 0x0A,
    0x72, 0x18, 0x6C, 0x73, 0x71, 0x73, 0x75
};

char renef_secret_buf[32];

JNIEXPORT jstring JNICALL
Java_com_byteria_labrenef_Case03Activity_getMemoryTarget(JNIEnv* env, jobject) {
    for (int i = 0; i < 15; i++) {
        renef_secret_buf[i] = (char)(ENC_KEY[i] ^ 0x41);
    }
    renef_secret_buf[15] = '\0';
    return env->NewStringUTF("MEMORY_TARGET_ACTIVE");
}

```

The critical points here are:

- ENC_KEY is decoded using XOR.
- The result is written into a global buffer named renef_secret_buf.
- Only the string "MEMORY_TARGET_ACTIVE" is returned to the Java layer.

##### Analysis Strategy

The approach followed in this scenario is:

- Verify whether libchallenge03.so is loaded
- Retrieve the base address
- Determine the offset of the global buffer
- Read the memory directly after the function call

This is not a classic return override scenario; it is an example of memory inspection.

##### Renef Lua Script

```lua

local lib = "libchallenge03.so"

local base = Module.find(lib)
if not base then
    print("[!] Library not loaded!")
    return
end

print("[+] " .. lib)
print("    Base: 0x" .. string.format("%x", base))

local exports = Module.exports(lib)
print("[+] Exports:")
for _, f in ipairs(exports) do
    print("    " .. f.name .. " @ 0x" .. string.format("%x", f.offset))
end
print("")

local buf_offset = 0x2a68

hook(lib, exports[1].offset, {
    onEnter = function(args)
        print("[*] " .. exports[1].name .. " called")
    end,
    onLeave = function(retval)
        local addr = base + buf_offset
        print("[*] Reading memory @ 0x" .. string.format("%x", addr))

        local data = Memory.read(addr, 32)

        local hex = ""
        for i = 1, 15 do
            hex = hex .. string.format("%02X ", string.byte(data, i))
        end
        print("[+] Raw: " .. hex)

        local secret = Memory.readStr(addr, 32)
        print("[+] Secret: " .. secret)
    end
})

print("[+] Hook ready!")

```

##### Script Explanation

```lua
local base = Module.find(lib)
```

Returns the base address of the library in memory. The global buffer address is calculated as base + offset.

```lua
Module.exports(lib)
```

Lists the exported symbols within the library. In this example, the first export corresponds to the target function.

```lua
local buf_offset = 0x2a68
```

This offset represents the relative address of the renef_secret_buf variable within the library.

```lua
local addr = base + buf_offset
local data = Memory.read(addr, 32)
```

At this point, the global buffer is read directly from memory.

```lua
string.format("%02X", string.byte(data, i))
```

The byte array in memory is converted into its hexadecimal representation using string.format("%02X"). This output reflects the raw memory view of the buffer content.

```lua
local secret = Memory.readStr(addr, 32)
```

Reads the buffer content as a null-terminated string.

![Renef Lab Cases - Memory Operations](/assets/img/renef-handbook/memory_operation_hook.png)

The output above demonstrates that the memory_operations_hook.lua script was successfully loaded via the Renef CLI and that the hook was triggered correctly.

- spawn com.byteria.labrenef launches the target application.
- l /data/local/tmp/memory_operations_hook.lua -w loads the Lua script and enables watch mode.
- Module.find("libchallenge03.so") retrieves the base address of the library.
- The export table is enumerated, and the symbol Java_com_byteria_labrenef_Case03Activity_getMemoryTarget is identified.
- When the function is invoked, the hook is triggered.
- The global buffer address is resolved by calculating base + buf_offset.
- The raw memory content is read using Memory.read().
- The decoded string is obtained using Memory.readStr().

#### 4.1.4 Memory Patch

In this scenario, the objective is to permanently alter the execution behavior of a native function by patching it at the instruction level.

In this case, a return override is not used. Instead, the function's machine code is modified directly.

##### Application Flow

On the Java side, when the button is pressed, the following native method is invoked:

```java

public native int isAllowed();

```

Native implementation:

```cpp
JNIEXPORT jint JNICALL
Java_com_byteria_labrenef_Case04Activity_isAllowed(JNIEnv*, jobject) {
    return 0;
}
```

The function always returns 0.

##### Analysis Strategy

The approach followed in this scenario is:

- Verify whether libchallenge04.so is loaded
- Identify the isAllowed function from the export table
- Calculate the function's actual runtime address
- Read the existing instructions
- Write new instructions at the ARM64 level
- Patch the function so that it directly returns 1

This is not a return override; it is a direct code patch.

##### ARM64 Instruction Patch

On ARM64:

```log
mov w0, #1  →  0x20008052
ret         →  0xC0035FD6
```

When these two instructions are written together, the function:

- Loads 1 into the w0 register
- Returns immediately

As a result, the function always returns 1.

##### Renef Lua Script

```lua

local lib = "libchallenge04.so"

local base = Module.find(lib)
if not base then
    print("[!] Library not loaded!")
    return
end
print("[+] " .. lib .. " @ 0x" .. string.format("%x", base))
print("")

local exports = Module.exports(lib)
local func
for _, f in ipairs(exports) do
    if f.name:find("isAllowed") then
        func = f
        break
    end
end

if not func then
    print("[-] isAllowed not found")
    return
end

print("[+] isAllowed @ +0x" .. string.format("%x", func.offset))
local func_addr = base + func.offset
print("[+] Address: 0x" .. string.format("%x", func_addr))
print("")

print("[*] Current bytes @ isAllowed:")
local data = Memory.read(func_addr, 16)
local hex = ""
for i = 1, 16 do
    hex = hex .. string.format("%02X ", string.byte(data, i))
end
print("    " .. hex)
print("")

print("[*] Patching isAllowed to return 1...")

local patch = "\x20\x00\x80\x52\xC0\x03\x5F\xD6"
local ok, err = Memory.patch(func_addr, patch)

if ok then
    print("[+] Patched!")
    print("")

    print("[*] Bytes after patch:")
    local after = Memory.read(func_addr, 16)
    local hex2 = ""
    for i = 1, 16 do
        hex2 = hex2 .. string.format("%02X ", string.byte(after, i))
    end
    print("    " .. hex2)
    print("")

else
    print("[-] Patch failed: " .. tostring(err))
end

```

```lua
local base = Module.find(lib)
```

Retrieves the library's runtime base address (since ASLR is enabled, this address may change on each execution).

```lua
if f.name:find("isAllowed")
```

Searches for the target symbol within the export list.

```lua
local func_addr = base + func.offset
```

The actual patch operation is applied to this calculated address.

```lua
Memory.read(func_addr, 16)
```

Displays the pre-patch instructions as a hex dump.

```lua
local patch = "\x20\x00\x80\x52\xC0\x03\x5F\xD6"
Memory.patch(func_addr, patch)
```

This byte sequence corresponds to:

```log
mov w0, #1
ret
```

The function now always returns 1.

After applying the patch, the same address is read again to verify that the new instructions have been written successfully.

![Renef Lab Cases - Memory Patch](/assets/img/renef-handbook/memory_patch_hook.png)

The output above demonstrates that the memory_patch_hook.lua script was successfully loaded via the Renef CLI and that the isAllowed() function was modified at the instruction level, altering its behavior.

- spawn com.byteria.labrenef launches the target application and returns the PID.
- l /data/local/tmp/memory_patch_hook.lua -w loads the Lua script and enables watch mode.
- libchallenge04.so @ 0x7e237df000 indicates the runtime base address of the target library.
- isAllowed @ +0x610 shows the offset of the relevant symbol in the export table.
- Address: 0x7e237df610 is the absolute function address obtained by calculating base + offset.
- Searching ret instructions (C0 03 5F D6)... indicates that memory scanning is performed using the ARM64 ret instruction byte pattern (C0 03 5F D6).
- Found 1000 ret(s) in libc.so shows that this pattern appears in multiple locations within libc, confirming that the scan was successful. (This scan is not strictly required for the patch itself; it serves primarily as a verification/example step.)
- Under Current bytes @ isAllowed:, the displayed hex sequence represents the raw memory view of the existing instructions at the function entry point.
- The line Patching isAllowed to return 1... indicates that the following byte sequence is written to the function entry:

    20 00 80 52 → mov w0, #1
    C0 03 5F D6 → ret

- Patched 8 bytes at 0x7e237df610 confirms that exactly 8 bytes were written and specifies the target address.
- Patched! indicates that the Memory.patch() call completed successfully.

- Under Bytes after patch:, the new hex sequence confirms that the function entry now begins with:

  20 00 80 52 C0 03 5F D6 ...

  This verifies that the patch has been permanently written into memory.

- From this point onward, when the button is pressed in the application, isAllowed() will always return 1, causing the execution flow to proceed through the "allowed" branch.

### 4.2 Java Hooking at the ART Level

#### 4.2.1 Java Method Hook

In this scenario, the objective is to hook a Java method running on ART at runtime in order to bypass the validation mechanism.

On the application side, there is a method named checkPasswordJava(String input). The method returns true only when the value "javasecret" is provided.

##### Application Flow

```java

private boolean checkPasswordJava(String input) {
    return input.equals("javasecret");
}

```

##### Analysis Strategy

In this scenario, the objective is to:

- Target the Case05Activity class
- Specify the checkPasswordJava method along with its signature
- Override the result via onEnter or onLeave

The method should be defined as follows:

```lua
hook("com/byteria/labrenef/Case05Activity",
     "checkPasswordJava",
     "(Ljava/lang/String;)Z", { ... })
```

Here:

- "com/byteria/labrenef/Case05Activity" → Class path
- "checkPasswordJava" → Method name
- "(Ljava/lang/String;)Z" → JNI method signature

##### Renef Lua Script - 1 (args.skip)

```lua

print(CYAN .. "Java Auth Bypass" .. RESET)

hook("com/byteria/labrenef/Case05Activity",
     "checkPasswordJava",
     "(Ljava/lang/String;)Z", {

    onEnter = function(args)
        args.skip = true
    end,

    onLeave = function(retval)
        return 1
    end
})

print(GREEN .. "Java hook installed!" .. RESET)

```

- When args.skip = true is used, the method body is not executed at all.
- Returning 1 inside onLeave ensures a boolean true result.
- As a result, the login succeeds regardless of the entered password.

![Renef Lab Cases - Java Method Hook](/assets/img/renef-handbook/java_method_hook.png)

The output above demonstrates that the Java-level hook was successfully installed and that method interception at the ART layer is active.

- spawn com.byteria.labrenef launches the target application and returns the PID.
- `l /data/local/tmp/java_auth_bypass.lua -w loads the Lua script and enables watch mode.

When the script is loaded:

- The Java Auth Bypass line is the initial output of the script.
- The Java hook installed! line confirms that the hook was successfully attached to the target Java method.

##### Renef Lua Script - 2

```lua

print("Hooking checkPasswordJava...")

hook("com/byteria/labrenef/Case05Activity",
     "checkPasswordJava",
     "(Ljava/lang/String;)Z", {

    onEnter = function(args)
        print("[CALLED] checkPasswordJava, input: " .. tostring(args[1]))
    end,

    onLeave = function(retval)
        print("Original: " .. tostring(retval))
        return 1
    end
})

print("Hook installed!")


```

- args[1] represents the first actual method parameter (String input).
-  The original return value is logged.
-  By returning 1, the result is forced to always evaluate to true.

![Renef Lab Cases - Java Method Hook - 2](/assets/img/renef-handbook/java_method_hook_2.png)

The output above shows that the java_auth_bypass_2.lua script was loaded and that the checkPasswordJava() method was logged at invocation time.

* spawn com.byteria.labrenef launches the application.
* l /data/local/tmp/java_auth_bypass_2.lua -w loads the script and enables watch mode.

After the script is loaded:

* Hooking checkPasswordJava... → initial log output of the script.
* Hook installed! → confirms that the hook was successfully attached.

When the method is triggered:

* [CALLED] checkPasswordJava, input: 315978808

The printed value here is not the actual String content. Renef does not directly display the Java String itself for args[1]; instead, it shows the JNI reference (a handle/pointer-like representation) associated with that object. Therefore, a plaintext value such as "javasecret" is not visible; what is logged is the reference to the method parameter.

* Original: table: 0xb400007dda5c3740

On the retval side, Java hooks often pass Renef's internal representation (a wrapper object) to Lua rather than the raw boolean value. As a result, calling tostring(retval) produces an output in the format table: 0x....

#### 4.2.2 Static Method Hook

In this scenario, the objective is to hook a static Java method defined on ART at runtime in order to bypass an access control mechanism.

The key difference in this case is that the target method is not an instance method, but a static method.

##### Application Flow

The static method is defined as follows:

```java

public static boolean checkAccess(String token) {
    boolean allowed = false;

    if (token != null) {
        if (token.length() > 3) {
            if (token.contains("ACCESS")) {
                if (token.equals("ACCESS_GRANTED")) {
                    allowed = true;
                }
            }
        }
    }
    return allowed;
}

```

##### Analysis Strategy

In this scenario, the objective is to:

- Target the Case06Activity class
- Specify the static checkAccess method along with its signature
- Force access by overriding the return value inside onLeave

When hooking a static method, an important distinction must be noted:

Unlike instance methods, there is no this object. However, on the Renef side, the hook definition follows the same format.

```lua

hook("com/byteria/labrenef/Case06Activity",
     "checkAccess",
     "(Ljava/lang/String;)Z", { ... })

```

##### Renef Lua Script

```lua

print("Hooking checkAccess...")

hook("com/byteria/labrenef/Case06Activity",
     "checkAccess",
     "(Ljava/lang/String;)Z", {

    onEnter = function(args)
        print("[CALLED] checkAccess, token: " .. tostring(args[1]))
    end,

    onLeave = function(retval)
        print("Original: " .. tostring(retval))
        return 1
    end
})

print("Hook installed!")


```

##### Script Explanation

```lua
onEnter = function(args)
    print("[CALLED] checkAccess, token: " .. tostring(args[1]))
end
```

- args[1] represents the first parameter of the method, which is the String token.
- Since this is a static method, there is no this reference.
- This allows the provided token to be observed at runtime.

```lua
onLeave = function(retval)
    return 1
end
```

- Regardless of the method's original return value, true is always returned.

![Renef Lab Cases - Static Method Hook](/assets/img/renef-handbook/static_method_hook.png)

The output above demonstrates that the checkAccess.lua script was successfully loaded and that the checkAccess() static method was hooked at runtime.

- spawn com.byteria.labrenef launches the target application and returns the PID.
- l /data/local/tmp/checkAccess.lua -w loads the script and enables watch mode.

When the script is loaded:

- Hooking checkAccess... → initial log output of the script.
- Hook installed! → confirms that the hook was successfully attached to the static method.

When the method is triggered:

- [CALLED] checkAccess, token: 317655344
The displayed value is not the actual plaintext token. Instead, it represents the JNI reference of the corresponding Java String object. For this reason, a pointer-like numeric value appears rather than the string content itself.

- Original: table: 0xb400007dda604080
The return value is also passed to Lua not as a raw boolean, but through Renef's internal representation. As a result, calling tostring(retval) produces an output in the format table: 0x....

## 5. Conclusion

Renef is a powerful tool for Android runtime analysis, providing dynamic intervention capabilities at both the native and ART levels. With its injection approach that does not rely on ptrace and its flexible Lua-based scripting model, it offers a robust framework for runtime instrumentation.

The lab scenarios presented in this article demonstrate the core capabilities of the framework through controlled and practical examples.

## 6. References and Additional Links

* Official Website: https://renef.io/
* Lua Script Platform: https://hook.renef.io/
* GitHub Repository: https://github.com/ahmeth4n/renef
