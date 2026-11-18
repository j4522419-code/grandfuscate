function announce(msg)
  lastMessage = msg
  return "said:" .. msg
end
print(announce("hi"))
print(lastMessage)
counter = 0
for i = 1, 3 do counter = counter + i end
print(counter)
print(type(print), type(nil), type(1), type("s"))
