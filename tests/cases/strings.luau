local a = "line\n\t\"quoted\" \065 \x42 \u{43}"
print(a, #a)
local b = [[long
string]]
print(b, #b)
local c = [==[has ]] inside]==]
print(c)
local name = "world"
local d = `hello {name} {1 + 2}`
print(d)
print(string.format("%s-%d", "x", 7))
print(string.byte("A"), string.char(66))
