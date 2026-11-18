Instance = { new = function(className)
  return {ClassName = className, Name = className, children = {},
    GetChildren = function(self) return self.children end,
    FindFirstChild = function(self, name)
      for _, c in ipairs(self.children) do if c.Name == name then return c end end
      return nil
    end,
    SetAttribute = function(self, k, v) self[k] = v end,
    GetAttribute = function(self, k) return self[k] end,
  }
end }
workspace = Instance.new("Workspace")
game = { GetService = function(_, name)
  return {Name = name, GetChildren = function() return {} end}
end }
task = { spawn = function(f, ...) return f(...) end, wait = function() return 0 end }
