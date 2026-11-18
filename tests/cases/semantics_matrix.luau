-- Differential matrix: multiple returns, errors, closures, upvalues,
-- globals, varargs, nil, tables, metatables, callbacks, self-calls,
-- nested functions, loops, coroutines and yielding.
local function many(...)
  return select("#", ...), ...
end
print("multi", many(1, nil, 3))

local ok, msg = pcall(function() error("boom") return 9 end)
print("pcall", ok, msg:match("boom") ~= nil)
local xok, xval = xpcall(
  function() error("xboom") end,
  function(e) return "handled:" .. tostring(e):match("xboom") end
)
print("xpcall", xok, xval)

GLOBAL_MATRIX = 11
print("globals", GLOBAL_MATRIX, _G.GLOBAL_MATRIX)

local t = {1, 2, nil, 4}
print("tables", #t, t[1], t[4], next(t) ~= nil)

local mt = {
  __index = function(_, k) return "idx:" .. k end,
  __newindex = function(_, k, v) rawset(_, k, "set:" .. v) end,
  __add = function(a, b) return (a.x or 0) + (b.x or 0) end,
  __call = function(_, x) return x * 2 end,
  __tostring = function() return "meta_t" end,
}
local a = setmetatable({x = 3}, mt)
local b = setmetatable({x = 4}, mt)
a.nope = "v"
print("meta", a.missing, a.nope, a + b, a(5), tostring(a), getmetatable(a) == mt)

local obj = {v = 2}
function obj:method(x)
  self.v = self.v + x
  return self.v, self
end
local function callback(f, ...)
  return f(...)
end
print(
  "method", obj:method(5), obj.v,
  callback(function(x, y) return x + y, nil, x * y end, 6, 7)
)

local co = coroutine.create(function(a)
  local b = coroutine.yield(a + 1)
  return a + b, "done"
end)
print("coroutine", coroutine.resume(co, 10))
print("coroutine2", coroutine.resume(co, 20))
print("coroutine3", coroutine.status(co))

local n = 0
for i = 1, 4 do
  if i == 2 then continue end
  n = n + i
end
while n < 20 do n = n + 1 end
repeat n = n + 1 until n >= 22
for k, v in ipairs({10, 20, 30}) do n = n + v end
print("loops", n)

local function outer(base)
  local c = base
  return function(step)
    c = c + step
    return c
  end
end
local c1, c2 = outer(0), outer(100)
print("closures", c1(1), c1(2), c2(1), c1(3))
print("nil", type(nil), tostring(nil), select("#", nil, nil))
print("varargs", many(7, 8, 9))
