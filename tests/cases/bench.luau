local acc = 0
for i = 1, 200000 do
  acc = acc + (i % 7) * 2 - 1
end
print(acc)
