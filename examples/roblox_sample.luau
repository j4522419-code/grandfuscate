--!strict
-- Example: a small server-side Roblox script.  All of this source disappears
-- in protected builds; only encoded data + a generated runtime remain.
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local SECRET_SALT = "px-2026-internal"
local MAX_HEALTH = 100

local function fingerprint(player: Player): string
	local id = tostring(player.UserId)
	return SECRET_SALT .. ":" .. id .. ":" .. tostring(MAX_HEALTH)
end

local function onPlayerAdded(player: Player)
	local leaderstats = Instance.new("Folder")
	leaderstats.Name = "leaderstats"
	leaderstats.Parent = player

	local health = Instance.new("IntValue")
	health.Name = "Health"
	health.Value = MAX_HEALTH
	health.Parent = leaderstats

	print("joined", fingerprint(player))
end

Players.PlayerAdded:Connect(onPlayerAdded)
ReplicatedStorage:SetAttribute("build", "protected")
