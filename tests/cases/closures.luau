local x = 10
local function outer(a)
  local y = a + x
  local function inner(b)
    return y + b + x
  end
  return inner
end
local f = outer(5)
print(f(1), f(2), outer(1)(3))
local funcs = {}
for i = 1, 3 do
  local j = i
  funcs[i] = function() return j end
end
print(funcs[1](), funcs[2](), funcs[3]())
do
  local x = 99
  print("shadow", x)
end
print("outer", x)
local a, a2 = 1, 2
do local a = 50; print(a) end
print(a, a2)
