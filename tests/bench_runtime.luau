local acc = 0
for i = 1, 5000 do
  acc = acc + (i % 7) * 2 - 1
end
print("bench", acc)
