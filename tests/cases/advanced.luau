local function makeCounter(base)
  local n = base
  return function(step)
    n = n + step
    return n
  end
end
local c1, c2 = makeCounter(10), makeCounter(100)
print("upvalues", c1(1), c1(2), c2(1))

local function many(...)
  local n = select("#", ...)
  local a, b = ...
  return n, a, b, ...
end
print("varargs", many(7, 8, 9))

local obj = {v = 2}
function obj:bump(x)
  self.v = self.v + x
  return self.v
end
print("method", obj:bump(3), obj.v)

local mt = {}
mt.__index = function(t, k) return "missing:" .. k end
mt.__call = function(t, x) return t.v + x end
mt.__add = function(a, b) return a.v + b.v end
local a = setmetatable({v = 4}, mt)
local b = setmetatable({v = 5}, mt)
print("meta", a.nope, a(3), a + b, getmetatable(a) == mt)

local co = coroutine.create(function(x)
  local y = coroutine.yield(x + 1)
  return x + y, "done"
end)
local ok1, v1 = coroutine.resume(co, 10)
local ok2, v2, v3 = coroutine.resume(co, 20)
print("coroutine", ok1, v1, ok2, v2, v3, coroutine.status(co))

local function apply(f, ...)
  return f(...)
end
print("callback", apply(function(a, b) return a * b, nil end, 6, 7))
print("nil", type(nil), tostring(nil), select("#", nil, nil))

local calls = 0
local t = {}
for i = 1, 3 do
  t[i] = function() calls = calls + i; return calls end
end
print("closures", t[1](), t[2](), t[3](), calls)
