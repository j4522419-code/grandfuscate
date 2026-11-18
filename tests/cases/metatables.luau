local mt = {}
mt.__index = function(t, k) return "missing:" .. k end
mt.__add = function(a, b) return a.v + b.v end
local a = setmetatable({v = 3}, mt)
local b = setmetatable({v = 4}, mt)
print(a.v, a.zzz, (a + b))
print(getmetatable(a) == mt)
