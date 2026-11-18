local part = Instance.new("Part")
part.Name = "TestPart"
workspace:SetAttribute("Part", part)
print("roblox", part.ClassName, part.Name, workspace:GetAttribute("Part") == part)
local service = game:GetService("Players")
print("service", service.Name)
local done = false
task.spawn(function(x) done = true; print("task", x) end, 42)
print("done", done)
local function handler(a, b) return a + b end
local ok, result = pcall(handler, 2, 3)
print("pcall", ok, result)
