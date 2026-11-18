local function pack(...)
  local n = select("#", ...)
  local t = {...}
  local sum = 0
  for i = 1, n do sum = sum + t[i] end
  return n, sum, ...
end
local a, b, c, d = pack(1, 2, 3)
print(a, b, c, d)
local function multi() return 4, 5 end
print(multi())
local x, y = multi()
print(x + y)
local ok = pcall(function() error("boom") end)
print("pcall", ok)
local function rec(n) if n <= 0 then return 0 end return n + rec(n - 1) end
print(rec(10))
