--[[
    Solance Anti-Reverse Engineering Shield v2
    Detects and punishes attempts to decompile, hook, spy on, or extract the cheat source.
    If a violation is detected, the user receives a permanent ban via Supabase.
    
    v2: Added whitelist system to prevent false positives from our own code.
]]

local AntiReverse = {}

-- Dependencies (injected from counterblox.lua)
local _SUPABASE_URL = nil
local _SUPABASE_KEY = nil
local _USER_ID = nil
local _REQUEST_FUNC = nil
local _LIBRARY = nil
local _TRIGGERED = false

-- Whitelist flag: when true, our own code is calling a hooked function
-- so the guard should let it through without punishing
local _SELF_CALL = false

function AntiReverse.Init(config)
    _SUPABASE_URL = config.supabase_url
    _SUPABASE_KEY = config.supabase_key
    _USER_ID = config.user_id
    _REQUEST_FUNC = config.request_func
    _LIBRARY = config.library
end

-- Allow our own cheat code to safely call hooked functions
function AntiReverse.AllowCall(fn)
    _SELF_CALL = true
    local results = {pcall(fn)}
    _SELF_CALL = false
    if results[1] then
        return unpack(results, 2)
    end
    return nil
end

-- ============================================================
-- CORE: Issue permanent ban and kick
-- ============================================================
local function Punish(reason)
    if _TRIGGERED then return end
    _TRIGGERED = true

    local banReason = "Anti-Reverse: " .. tostring(reason)

    -- 1. Write ban to database
    pcall(function()
        if _REQUEST_FUNC and _USER_ID and _SUPABASE_URL then
            _REQUEST_FUNC({
                Url = _SUPABASE_URL .. "/rest/v1/profiles?id=eq." .. _USER_ID,
                Method = "PATCH",
                Headers = {
                    ["apikey"] = _SUPABASE_KEY,
                    ["Authorization"] = "Bearer " .. _SUPABASE_KEY,
                    ["Content-Type"] = "application/json",
                    ["Prefer"] = "return=minimal"
                },
                Body = game:GetService("HttpService"):JSONEncode({
                    is_banned = true,
                    ban_reason = banReason,
                    ban_expires_at = nil -- permanent
                })
            })
        end
    end)

    -- 2. Notify + Kick
    pcall(function()
        if _LIBRARY and _LIBRARY.NotifyError then
            _LIBRARY:NotifyError("[solance] reverse engineering detected. you have been permanently banned.", 15)
        end
    end)

    task.delay(0.5, function()
        pcall(function()
            local lp = game:GetService("Players").LocalPlayer
            if lp then lp:Kick("\n[solance]\npermanently banned: " .. banReason) end
        end)
    end)
end

-- ============================================================
-- GUARD 1: Anti-Spy (Remote Spy / Script Spy detection)
-- ============================================================
local function Guard_AntiSpy()
    local spySignatures = {
        "simplespy", "remotespy", "hydroxide", "dex", "dexv4",
        "infyield", "scriptdumper", "synapsexen", "oh_gui",
        "simplespy_main", "remote_spy", "httpspy"
    }

    task.spawn(function()
        while true do
            if _TRIGGERED then break end
            if _LIBRARY and _LIBRARY.Unloaded then break end
            pcall(function()
                for _, gui in pairs(game:GetService("CoreGui"):GetChildren()) do
                    if gui:IsA("ScreenGui") then
                        local name = string.lower(gui.Name)
                        for _, sig in ipairs(spySignatures) do
                            if string.find(name, sig) then
                                Punish("remote spy detected: " .. gui.Name)
                                return
                            end
                        end
                    end
                end

                local pgui = game:GetService("Players").LocalPlayer:FindFirstChild("PlayerGui")
                if pgui then
                    for _, gui in pairs(pgui:GetChildren()) do
                        if gui:IsA("ScreenGui") then
                            local name = string.lower(gui.Name)
                            for _, sig in ipairs(spySignatures) do
                                if string.find(name, sig) then
                                    Punish("spy tool in PlayerGui: " .. gui.Name)
                                    return
                                end
                            end
                        end
                    end
                end
            end)
            task.wait(3)
        end
    end)
end

-- ============================================================
-- GUARD 2: Anti-Decompile (debug library snooping)
-- ============================================================
local function Guard_AntiDecompile()
    local _protectedClosures = {}

    function AntiReverse.Protect(fn)
        _protectedClosures[fn] = true
        return fn
    end

    local function wrapDebug(name)
        local lib = debug
        if not lib then return end
        local original = rawget(lib, name)
        if not original then return end

        rawset(lib, name, function(fn, ...)
            if not _SELF_CALL and type(fn) == "function" and _protectedClosures[fn] then
                Punish(name .. " called on protected function")
            end
            return original(fn, ...)
        end)
    end

    wrapDebug("getinfo")
    wrapDebug("getupvalue")
    wrapDebug("setupvalue")
    wrapDebug("getupvalues")
    wrapDebug("getconstants")
    wrapDebug("getprotos")
end

-- ============================================================
-- GUARD 3: Anti-getgc (GC table scanning)
-- Only triggers for EXTERNAL callers, not our own code
-- ============================================================
local function Guard_AntiGetGC()
    if not getgc then return end
    
    local realGetGC = getgc
    getgc = function(...)
        if not _SELF_CALL then
            Punish("getgc called — gc scanning attempt")
        end
        return realGetGC(...)
    end
end

-- ============================================================
-- GUARD 4: Anti-hookfunction on critical functions
-- ============================================================
local function Guard_AntiHookFunction()
    if not hookfunction then return end

    local criticalFuncs = {}
    
    local function snapshot(name, fn)
        if fn then
            criticalFuncs[name] = {
                ref = fn,
                addr = tostring(fn)
            }
        end
    end

    snapshot("request", _REQUEST_FUNC)
    snapshot("hookmetamethod", hookmetamethod)
    snapshot("newcclosure", newcclosure)

    task.spawn(function()
        while true do
            if _TRIGGERED then break end
            if _LIBRARY and _LIBRARY.Unloaded then break end
            for name, data in pairs(criticalFuncs) do
                if tostring(data.ref) ~= data.addr then
                    Punish("critical function tampered: " .. name)
                    return
                end
            end
            task.wait(5)
        end
    end)
end

-- ============================================================
-- GUARD 5: Anti-SaveInstance
-- ============================================================
local function Guard_AntiSaveInstance()
    if saveinstance then
        local realSave = saveinstance
        saveinstance = function(...)
            if not _SELF_CALL then
                Punish("saveinstance called — game dump attempt")
            end
            return realSave(...)
        end
    end

    if saveplace then
        local realSave = saveplace
        saveplace = function(...)
            if not _SELF_CALL then
                Punish("saveplace called — game dump attempt")
            end
            return realSave(...)
        end
    end
end

-- ============================================================
-- GUARD 6: Anti-getsenv (Script Environment sniffing)
-- Whitelisted for our own skinchanger code
-- ============================================================
local function Guard_AntiGetSenv()
    if not getsenv then return end

    local realGetsenv = getsenv
    getsenv = function(scr, ...)
        if not _SELF_CALL then
            Punish("getsenv called — script environment dump attempt")
        end
        return realGetsenv(scr, ...)
    end
end

-- ============================================================
-- GUARD 7: Anti-Decompile function (decompile / disassemble)
-- ============================================================
local function Guard_AntiDecompileFunc()
    if decompile then
        local realDecompile = decompile
        decompile = function(fn, ...)
            if not _SELF_CALL then
                Punish("decompile() called — source extraction attempt")
            end
            return realDecompile(fn, ...)
        end
    end

    if disassemble then
        local realDisassemble = disassemble
        disassemble = function(fn, ...)
            if not _SELF_CALL then
                Punish("disassemble() called — bytecode extraction attempt")
            end
            return realDisassemble(fn, ...)
        end
    end
end

-- ============================================================
-- GUARD 8: Anti-getscripts (Script enumeration)
-- ============================================================
local function Guard_AntiGetScripts()
    if not getscripts then return end

    local realGetScripts = getscripts
    getscripts = function(...)
        if not _SELF_CALL then
            Punish("getscripts called — script enumeration attempt")
        end
        return realGetScripts(...)
    end
end

-- ============================================================
-- GUARD 9: Anti-require flood (ModuleScript mass extraction)
-- ============================================================
local function Guard_AntiRequire()
    if not require then return end

    local requireCount = 0
    local requireWindow = tick()
    local realRequire = require

    require = function(mod, ...)
        if not _SELF_CALL then
            requireCount = requireCount + 1
            -- Reset counter every 10 seconds
            if (tick() - requireWindow) > 10 then
                requireCount = 1
                requireWindow = tick()
            end
            -- If someone is mass-requiring (>15 in 10 seconds), that's reversing
            if requireCount > 15 then
                Punish("mass require detected — module extraction attempt")
            end
        end
        return realRequire(mod, ...)
    end
end

-- ============================================================
-- GUARD 10: Integrity check — verify auth wasn't spoofed
-- ============================================================
local function Guard_IntegrityCheck()
    task.spawn(function()
        while true do
            if _TRIGGERED then break end
            if _LIBRARY and _LIBRARY.Unloaded then break end
            task.wait(15)

            if not getgenv().Solance_CounterBlox_Loaded and not (_LIBRARY and _LIBRARY.Unloaded) then
                Punish("loaded flag cleared externally — injection bypass attempt")
                break
            end

            if _LIBRARY and _LIBRARY._SolanceIntegrity then
                if _LIBRARY._SolanceIntegrity ~= "verified" then
                    Punish("library integrity check failed — object was replaced")
                    break
                end
            end
        end
    end)
end

-- ============================================================
-- GUARD 11: Anti-HttpSpy (detect interception of API calls)
-- ============================================================
local function Guard_AntiHttpSpy()
    task.spawn(function()
        while true do
            if _TRIGGERED then break end
            if _LIBRARY and _LIBRARY.Unloaded then break end
            task.wait(8)

            pcall(function()
                if _REQUEST_FUNC and _SUPABASE_URL then
                    local canary = _REQUEST_FUNC({
                        Url = _SUPABASE_URL .. "/rest/v1/profiles?select=id&id=eq.canary_check_" .. tostring(math.random(100000, 999999)),
                        Method = "GET",
                        Headers = {
                            ["apikey"] = _SUPABASE_KEY,
                            ["Authorization"] = "Bearer " .. _SUPABASE_KEY,
                            ["Content-Type"] = "application/json"
                        }
                    })
                    if canary and canary.StatusCode ~= 200 then
                        Punish("http request interception detected")
                    end
                end
            end)
        end
    end)
end

-- ============================================================
-- START ALL GUARDS
-- ============================================================
function AntiReverse.Start()
    if not _USER_ID then return end

    Guard_AntiSpy()
    Guard_AntiDecompile()
    Guard_AntiGetGC()
    Guard_AntiHookFunction()
    Guard_AntiSaveInstance()
    Guard_AntiGetSenv()
    Guard_AntiDecompileFunc()
    Guard_AntiGetScripts()
    Guard_AntiRequire()
    Guard_IntegrityCheck()
    Guard_AntiHttpSpy()
end

return AntiReverse
