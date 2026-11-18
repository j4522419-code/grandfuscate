local total = 0
for i = 1, 10 do
  if i % 2 == 0 then
    total = total + i
  elseif i == 7 then
    total = total + 100
    break
  else
    total = total - 1
  end
end
print("total", total)
local w = 0
while true do
  w = w + 1
  if w >= 5 then break end
  if w == 2 then continue end
  total = total + w
end
print("w", w, "total", total)
local r = 0
repeat
  r = r + 1
until r >= 4
print("r", r)
local function classify(n)
  if n < 0 then return "neg" end
  if n == 0 then return "zero" end
  return "pos"
end
print(classify(-1), classify(0), classify(3))
local function early(n)
  if n == 1 then return 1, 2 end
  return 3
end
print(early(1))
print(early(2))
