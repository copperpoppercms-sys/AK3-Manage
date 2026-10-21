"""Generate an original Roblox key prompt; source payload stays behind authorization."""
from urllib.parse import urlsplit


def public_url(value):
    value = value.rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or parsed.path:
        raise ValueError("PUBLIC_BASE_URL must be an HTTPS origin, such as https://your-app.example")
    parsed.port  # Validate a configured port, if present.
    return value


def quote(value):
    return '"' + ''.join(chr(byte) if 32 <= byte < 127 and byte not in (34, 92) else '\\%03d' % byte for byte in value.encode('utf-8')) + '"'


def short_loader(base, script_id):
    return "loadstring(game:HttpGet(%s))()" % quote(public_url(base) + "/v1/loader/" + script_id)


def bootstrap(base, script):
    replacements = {
        "__BASE__": quote(public_url(base)), "__SCRIPT__": quote(script["id"]),
        "__NAME__": quote(script["name"]), "__ACCENT__": quote(script["accent"]),
    }
    source = '''-- A3K Bastion: authenticated script access
local base, scriptId, hubName, accentHex = __BASE__, __SCRIPT__, __NAME__, __ACCENT__
local http = game:GetService("HttpService")
local player = game:GetService("Players").LocalPlayer
if not player then error("Bastion requires a local player") end
local requestFn = request or http_request or (syn and syn.request)
if type(requestFn) ~= "function" then
    error("This runtime does not provide the HTTP request function required by Bastion")
end
local deviceOk, device = pcall(function()
    return game:GetService("RbxAnalyticsService"):GetClientId()
end)
if not deviceOk or type(device) ~= "string" or #device < 8 then
    error("Bastion could not obtain a device identifier")
end
local function send(method, path, headers, body)
    local response = requestFn({Url=base..path, Method=method, Headers=headers, Body=body})
    if type(response) ~= "table" then error("Invalid network response") end
    return response.StatusCode or response.Status or 0, response.Body or ""
end
local gui = Instance.new("ScreenGui")
gui.Name = "A3KBastion"
gui.ResetOnSpawn = false
gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
gui.Parent = player:WaitForChild("PlayerGui")
local panel = Instance.new("Frame")
panel.AnchorPoint = Vector2.new(0.5,0.5)
panel.Position = UDim2.fromScale(0.5,0.5)
panel.Size = UDim2.fromOffset(352,270)
panel.BackgroundColor3 = Color3.fromRGB(15,23,42)
panel.BorderSizePixel = 0
panel.Parent = gui
local corner = Instance.new("UICorner")
corner.CornerRadius = UDim.new(0,16)
corner.Parent = panel
local accent = Color3.fromHex(accentHex)
local stroke = Instance.new("UIStroke")
stroke.Color = accent
stroke.Thickness = 1.5
stroke.Parent = panel
local function label(text, y, size, color)
    local value = Instance.new("TextLabel")
    value.BackgroundTransparency = 1
    value.Position = UDim2.fromOffset(22,y)
    value.Size = UDim2.new(1,-44,0,28)
    value.Font = Enum.Font.GothamBold
    value.TextSize = size
    value.TextColor3 = color
    value.Text = text
    value.TextTruncate = Enum.TextTruncate.AtEnd
    value.Parent = panel
    return value
end
label("A3K  /  BASTION",18,12,accent)
label(hubName,52,23,Color3.fromRGB(241,245,249))
label("Enter the access key issued by the owner",84,12,Color3.fromRGB(148,163,184))
local input = Instance.new("TextBox")
input.Position = UDim2.fromOffset(22,125)
input.Size = UDim2.new(1,-44,0,42)
input.BackgroundColor3 = Color3.fromRGB(30,41,59)
input.BorderSizePixel = 0
input.TextColor3 = Color3.fromRGB(241,245,249)
input.Font = Enum.Font.Code
input.TextSize = 14
input.PlaceholderText = "BAS-..."
input.Text = ""
input.ClearTextOnFocus = false
input.Parent = panel
local inputCorner = Instance.new("UICorner")
inputCorner.CornerRadius = UDim.new(0,8)
inputCorner.Parent = input
local button = Instance.new("TextButton")
button.Position = UDim2.fromOffset(22,180)
button.Size = UDim2.new(1,-44,0,42)
button.BackgroundColor3 = accent
button.BorderSizePixel = 0
button.TextColor3 = Color3.fromRGB(15,23,42)
button.Font = Enum.Font.GothamBold
button.TextSize = 14
button.Text = "Unlock script"
button.Parent = panel
local buttonCorner = Instance.new("UICorner")
buttonCorner.CornerRadius = UDim.new(0,8)
buttonCorner.Parent = button
local status = label("Private keys. Controlled access.",233,11,Color3.fromRGB(148,163,184))
local busy = false
button.MouseButton1Click:Connect(function()
    if busy then return end
    local key = input.Text:match("^%s*(.-)%s*$")
    if #key < 20 then status.Text = "Enter your complete access key."; return end
    busy = true
    button.Text = "Checking access..."
    local ok, result = pcall(function()
        local code, body = send("POST","/v1/auth/"..scriptId,
            {["Content-Type"]="application/json"},http:JSONEncode({key=key,device=device}))
        local decodeOk, data = pcall(function() return http:JSONDecode(body) end)
        if not decodeOk or type(data) ~= "table" then return "The access server is unavailable." end
        if code ~= 200 then return data.error or "Access denied." end
        if type(data.access_token) ~= "string" then return "Invalid access grant." end
        local payloadCode, payload = send("GET","/v1/payload/"..scriptId,
            {Authorization="Bearer "..data.access_token,["X-Bastion-Device"]=device},nil)
        if payloadCode ~= 200 then return "The download grant expired or access was revoked. Try again." end
        local chunk, compileError = loadstring(payload, "Bastion/"..hubName)
        if not chunk then return "The uploaded script could not compile in this runtime." end
        input.Text = ""
        gui:Destroy()
        task.spawn(function()
            local ran, failure = pcall(chunk)
            if not ran then warn("Bastion script error: "..tostring(failure)) end
        end)
        return nil
    end)
    if gui.Parent then
        status.Text = ok and (result or "Access granted.") or "Could not connect. Try again."
        button.Text = "Unlock script"
        busy = false
    end
end)
'''
    # One pass prevents a chosen hub name from being interpreted as a template tag.
    import re
    return re.sub(r"__(?:BASE|SCRIPT|NAME|ACCENT)__", lambda match: replacements[match.group(0)], source)
