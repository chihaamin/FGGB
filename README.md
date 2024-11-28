# Frida GameGuardian Bridge (FGGB)
It is a work-around to be able to run frida script from GG script. ( still require frida-server to be running use [Magisk-Frida](https://github.com/ViRb3/magisk-frida) ) 

Using Rust bindings for [Frida](https://frida.re).[![docs.rs](https://docs.rs/frida/badge.svg)](https://docs.rs/frida)

# NOTE: ARCH64 support only

# Usage
just Download [Magisk-FGGB](https://github.com/chihaamin/FGGB-Magisk) or Download the binary in release and run it using adb or termux.

Boilerplate GG Script : 
```lua
--[[
http://localhost:6699: is the default endpoint accept only POST request ( for now )
pid: is the target pid you want to inject ur script into
GG: is GameGuardian package name
["content-length"] is mendatory
["user-agent"] = gg.PACKAGE will be mendatory in further releases
]]
local pid = gg.getTargetInfo().pid
local script = [[console.log(Process.id)]]

local req = gg.makeRequest( 
    string.format("http://localhost:6699?pid=%d&GG=%s", pid, gg.PACKAGE),
    {
        ["content-length"] = script:len(),
        ["user-agent"] = gg.PACKAGE,
    },
    script
)
```
