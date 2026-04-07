--[[
    Solance Anti-Reverse Engineering Shield
    Detects and punishes attempts to decompile, hook, spy on, or extract the cheat source.
    If a violation is detected, the user receives a permanent ban via Supabase.
]]

local AntiReverse = {}

-- Dependencies (injected from counterblox.lua)
local _SUPABASE_URL = nil
local _SUPABASE_KEY = nil
local _USER_ID = nil
local _REQUEST_FUNC = nil
local _LIBRARY = nil
local _TRIGGERED = false

function AntiReverse.Init(config)
    _SUPABASE_URL = config.supabase_url
    _SUPABASE_KEY = config.supabase_key
    _USER_ID = config.user_id
    _REQUEST_FUNC = config.request_func
    _LIBRARY = config.library
end

-- ============================================================
-- CORE: Issue permanent ban and kick
-- ============================================================
local function Punish(reason)
    if _TRIGGERED then return end
    _TRIGGERED = true

    local banReason = "anti-reverse: " .. tostring(reason)

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
    -- Common remote spy tools create ScreenGuis with known names
    local spySignatures = {
        "SimpleSpy", "RemoteSpy", "Hydroxide", "Dex", "DexV4",
        "InfYield", "ScriptDumper", "SynapseXen", "OH_GUI",
        "SimpleSpy_Main", "remote_spy", "HttpSpy"
    }

    task.spawn(function()
        while true do
            if _TRIGGERED then break end
            pcall(function()
                -- Check CoreGui for spy tools
                for _, gui in pairs(game:GetService("CoreGui"):GetChildren()) do
                    if gui:IsA("ScreenGui") then
                        local name = string.lower(gui.Name)
                        for _, sig in ipairs(spySignatures) do
                            if string.find(name, string.lower(sig)) then
                                Punish("remote spy detected: " .. gui.Name)
                                return
                            end
                        end
                    end
                end

                -- Check PlayerGui too
                local pgui = game:GetService("Players").LocalPlayer:FindFirstChild("PlayerGui")
                if pgui then
                    for _, gui in pairs(pgui:GetChildren()) do
                        if gui:IsA("ScreenGui") then
                            local name = string.lower(gui.Name)
                            for _, sig in ipairs(spySignatures) do
                                if string.find(name, string.lower(sig)) then
                                    Punish("spy tool detected in PlayerGui: " .. gui.Name)
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
-- GUARD 2: Anti-Decompile (debug.getinfo / debug.getupvalue)
-- ============================================================
local function Guard_AntiDecompile()
    -- Wrap debug functions to detect snooping on our closures
    local _protectedClosures = {}

    function AntiReverse.Protect(fn)
        _protectedClosures[fn] = true
        return fn
    end

    -- Monitor debug.getinfo
    if debug and debug.getinfo then
        local realGetInfo = debug.getinfo
        debug.getinfo = function(fn, ...)
            if type(fn) == "function" and _protectedClosures[fn] then
                Punish("debug.getinfo called on protected function")
            end
            return realGetInfo(fn, ...)
        end
    end

    -- Monitor debug.getupvalue
    if debug and debug.getupvalue then
        local realGetUpvalue = debug.getupvalue
        debug.getupvalue = function(fn, ...)
            if type(fn) == "function" and _protectedClosures[fn] then
                Punish("debug.getupvalue called on protected function")
            end
            return realGetUpvalue(fn, ...)
        end
    end

    -- Monitor debug.setupvalue
    if debug and debug.setupvalue then
        local realSetUpvalue = debug.setupvalue
        debug.setupvalue = function(fn, ...)
            if type(fn) == "function" and _protectedClosures[fn] then
                Punish("debug.setupvalue called on protected function")
            end
            return realSetUpvalue(fn, ...)
        end
    end

    -- Monitor debug.getupvalues (plural, some executors have this)
    if debug and rawget(debug, "getupvalues") then
        local realGetUpvalues = debug.getupvalues
        debug.getupvalues = function(fn, ...)
            if type(fn) == "function" and _protectedClosures[fn] then
                Punish("debug.getupvalues called on protected function")
            end
            return realGetUpvalues(fn, ...)
        end
    end

    -- Monitor debug.getconstants
    if debug and rawget(debug, "getconstants") then
        local realGetConstants = debug.getconstants
        debug.getconstants = function(fn, ...)
            if type(fn) == "function" and _protectedClosures[fn] then
                Punish("debug.getconstants called on protected function")
            end
            return realGetConstants(fn, ...)
        end
    end

    -- Monitor debug.getprotos
    if debug and rawget(debug, "getprotos") then
        local realGetProtos = debug.getprotos
        debug.getprotos = function(fn, ...)
            if type(fn) == "function" and _protectedClosures[fn] then
                Punish("debug.getprotos called on protected function")
            end
            return realGetProtos(fn, ...)
        end
    end
end

-- ============================================================
-- GUARD 3: Anti-getgc (GC table scanning)
-- ============================================================
local function Guard_AntiGetGC()
    if not getgc then return end
    
    local realGetGC = getgc
    getgc = function(...)
        -- If someone calls getgc while our cheat is loaded, flag it
        -- (legitimate scripts almost never call getgc)
        Punish("getgc called — gc scanning attempt")
        return realGetGC(...)
    end
end

-- ============================================================
-- GUARD 4: Anti-hookfunction on critical functions
-- ============================================================
local function Guard_AntiHookFunction()
    if not hookfunction then return end

    -- Store fingerprints of critical executor functions we use
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

    -- Periodically verify nobody replaced our critical functions
    task.spawn(function()
        while true do
            if _TRIGGERED then break end
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
    -- Detect saveinstance / saveplace calls
    if saveinstance then
        local realSave = saveinstance
        saveinstance = function(...)
            Punish("saveinstance called — game dump attempt")
            return realSave(...)
        end
    end

    if saveplace then
        local realSave = saveplace
        saveplace = function(...)
            Punish("saveplace called — game dump attempt")
            return realSave(...)
        end
    end
end

-- ============================================================
-- GUARD 6: Anti-getsenv (Script Environment sniffing)
-- ============================================================
local function Guard_AntiGetSenv()
    -- Not all executors have getsenv
    if not getsenv then return end

    local realGetsenv = getsenv
    getsenv = function(scr, ...)
        -- Only flag if they're scanning scripts while our cheat runs
        -- This is almost always used for reversing
        Punish("getsenv called — script environment dump attempt")
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
            Punish("decompile() called — source extraction attempt")
            return realDecompile(fn, ...)
        end
    end

    if disassemble then
        local realDisassemble = disassemble
        disassemble = function(fn, ...)
            Punish("disassemble() called — bytecode extraction attempt")
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
        Punish("getscripts called — script enumeration attempt")
        return realGetScripts(...)
    end
end

-- ============================================================
-- GUARD 9: Anti-require hook (ModuleScript extraction)
-- ============================================================
local function Guard_AntiRequire()
    if not require then return end

    -- Monitor if someone is trying to require game modules to reverse them
    -- We wrap the global require to detect bulk scanning
    local requireCount = 0
    local requireStart = tick()
    local realRequire = require

    require = function(mod, ...)
        requireCount = requireCount + 1
        -- If someone is mass-requiring modules (>10 in 5 seconds), that's sus
        if requireCount > 10 and (tick() - requireStart) < 5 then
            Punish("mass require detected — module extraction attempt")
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
            task.wait(15)

            -- Verify the Solance_CounterBlox_Loaded flag hasn't been cleared externally
            -- (someone trying to re-inject while bypassing the duplicate check)
            if not getgenv().Solance_CounterBlox_Loaded and not (_LIBRARY and _LIBRARY.Unloaded) then
                Punish("loaded flag was cleared externally — injection bypass attempt")
                break
            end

            -- Verify the Library object hasn't been swapped out
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
-- GUARD 11: Anti-HttpSpy (detect interception of our API calls)
-- ============================================================
local function Guard_AntiHttpSpy()
    task.spawn(function()
        while true do
            if _TRIGGERED then break end
            task.wait(8)

            -- Send a canary request to our own endpoint
            -- If someone is intercepting HTTP, they might modify or log this
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
                    -- If the request was intercepted and changed, StatusCode won't be 200
                    -- (a properly configured Supabase will return 200 with empty array for non-existent IDs)
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
    if not _USER_ID then return end -- can't issue bans without user id

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
