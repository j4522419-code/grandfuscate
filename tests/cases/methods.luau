local obj = { value = 7 }
function obj:add(n)
  self.value = self.value + n
  return self.value
end
print(obj:add(3), obj.value)
function obj.sub(self, n) return self.value - n end
print(obj:sub(2))
local t = { inner = { deep = 5 } }
print(t.inner.deep)
t.inner.deep = 9
print(t["inner"]["deep"], t.inner.deep)
print(math.max(1, 5), math.floor(3.7), table.concat({1, 2, 3}, ","))
print(("abc"):rep(2), ("x"):upper())
