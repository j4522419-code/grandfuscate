--!strict
local x: number = 5
local function f(a: number, b: string): string
  return b .. tostring(a :: number)
end
print(f(x, "v="))
type Pair = { a: number, b: string }
local p: Pair = { a = 1, b = "two" }
print(p.a, p.b)
local maybe: number? = nil
print(maybe == nil)
