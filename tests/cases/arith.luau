local a = 12
local b = 3.5
local s = "hello"
print(a + b, a * b, a % 5, a ^ 2, -a, #s)
print(s .. " world", s:upper(), string.sub(s, 2, 3))
print(0x10, 0b101, 1e3, 1e-2, .5)
local t = {1, 2, 3, foo = 4, ["bar"] = 5}
for i, v in ipairs(t) do print(i, v) end
print(t[1], t.foo, t["bar"], #t, t.foo + t["bar"])
print(true, false, nil, not true, 1 == 1, 2 ~= 3)
local n = 0
n += 7
n *= 2
print(n, n // 4, bit32.band(n, 3), bit32.bor(n, 8), bit32.bxor(n, 1), bit32.lshift(n, 2), bit32.rshift(n, 1))
