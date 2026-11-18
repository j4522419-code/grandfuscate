-- Third-pass differential fixture: closures, upvalues, varargs, multiple
-- returns, nil, tables, metatables, callbacks, method calls, errors,
-- coroutines, yielding and control flow. All output is deterministic.
local function variadic(...)
  local n = select("#", ...)
  local a, b, c = ...
  return n, a, b, c
end
print("varargs", variadic(7, nil, 9))

local function outer(base)
  local count = base
  return function(step)
    count = count + step
    return count, base
  end
end
local one, two = outer(0), outer(100)
print("closures", one(1), two(2), one(3))

local meta = {
  __index = function(_, k) return "idx:" .. k end,
  __newindex = function(t, k, v) rawset(t, k, "set:" .. v) end,
  __add = function(a, b) return (a.x or 0) + (b.x or 0) end,
  __call = function(_, x) return x * 2 end,
  __tostring = function() return "meta_v3" end,
}
local a = setmetatable({ x = 3 }, meta)
local b = setmetatable({ x = 4 }, meta)
a.missing_value = "v"
print("meta", a.absent, a.missing_value, a + b, a(5), tostring(a), getmetatable(a) == meta)

local obj = { value = 2 }
function obj:method(x, y)
  self.value = self.value + x
  return self.value, y
end
local function callback(f, ...)
  return f(...)
end
print(
  "method", obj:method(5, 6), obj.value,
  callback(function(x, y) return x + y end, 8, 9)
)

local ok, msg = pcall(function() error("boom_v3") return 9 end)
print("pcall", ok, tostring(msg):match("boom_v3") ~= nil)
local xok, xval = xpcall(
  function() error("xboom_v3") end,
  function(e) return "handled:" .. tostring(e):match("xboom_v3") end
)
print("xpcall", xok, xval)

GLOBAL_V3 = 11
print("globals", GLOBAL_V3, _G.GLOBAL_V3)
local t = { 1, 2, nil, 4 }
print("tables", #t, t[1], t[4], next(t) ~= nil)

local co = coroutine.create(function(a)
  local b = coroutine.yield(a + 1)
  return a + b, "done_v3"
end)
print("coroutine", coroutine.resume(co, 10))
print("coroutine2", coroutine.resume(co, 20))
print("coroutine3", coroutine.status(co))

local n = 0
for i = 1, 5 do
  if i == 2 then continue end
  n = n + i
end
while n < 24 do n = n + 1 end
repeat n = n + 1 until n >= 26
for _, v in ipairs({ 10, 20, 30 }) do n = n + v end
print("loops", n)
print("nil", type(nil), tostring(nil), select("#", nil, nil))
