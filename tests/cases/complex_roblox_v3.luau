-- Self-contained mocked Roblox API fixture. It exercises Instance.new,
-- game:GetService, workspace attributes, task.spawn, event callbacks,
-- : method calls, pcall, varargs, multiple returns, closures, upvalues,
-- metatables and a coroutine that yields through an event-like Wait method.
Instance = {
  new = function(className)
    local object = {
      ClassName = className,
      Name = className,
      _attributes = {},
      _children = {},
    }
    function object:SetAttribute(key, value)
      self._attributes[key] = value
    end
    function object:GetAttribute(key)
      return self._attributes[key]
    end
    function object:GetChildren()
      return self._children
    end
    function object:FindFirstChild(name)
      for _, child in ipairs(self._children) do
        if child.Name == name then return child end
      end
      return nil
    end
    if className == "BindableEvent" then
      local event = { _connections = {} }
      function event:Connect(callback)
        self._connections[#self._connections + 1] = callback
        return { Connected = true }
      end
      function event:Fire(...)
        local first = nil
        for _, callback in ipairs(self._connections) do
          local value = callback(...)
          if first == nil then first = value end
        end
        return #self._connections, first
      end
      function event:Wait()
        return coroutine.yield()
      end
      object.Event = event
    end
    return object
  end,
}
workspace = Instance.new("Workspace")
game = {
  GetService = function(_, name)
    local service = Instance.new(name)
    service.Name = name
    return service
  end,
}
task = {
  spawn = function(callback, ...)
    return callback(...)
  end,
  wait = function()
    return 0
  end,
}

local part = Instance.new("Part")
part.Name = "ThirdPassPart"
workspace:SetAttribute("Part", part)
local service = game:GetService("Players")
print("roblox", part.ClassName, part.Name, workspace:GetAttribute("Part") == part, service.Name)

local event = Instance.new("BindableEvent")
local calls = 0
local upvalue = 10
local function callback(a, b)
  calls = calls + 1
  return a + b + upvalue
end
local connection = event.Event:Connect(callback)
local count, first = event.Event:Fire(2, 3)
print("event", count, first, connection.Connected, calls)

local co = coroutine.create(function(...)
  local a, b = event.Event:Wait()
  local n = select("#", ...)
  return a + b, n, "resumed_v3"
end)
print("wait_start", coroutine.resume(co, 1, 2))
print("wait_resume", coroutine.resume(co, 4, 5))
print("wait_status", coroutine.status(co))

local spawned_total = 0
task.spawn(function(...)
  local n = select("#", ...)
  for i = 1, n do spawned_total = spawned_total + (select(i, ...) or 0) end
end, 1, 2, 3)
print("task", spawned_total, task.wait())

local protected = pcall(function(a, b) return a // b end, 8, 2)
print("pcall", protected)

local mt = {
  __index = function(_, key) return "missing:" .. key end,
  __tostring = function() return "roblox_meta_v3" end,
}
local proxy = setmetatable({ x = 7 }, mt)
print("meta", proxy.x, proxy.unknown, tostring(proxy))

local function variadic(...)
  return select("#", ...), ...
end
print("varargs", variadic(6, nil, 8))
