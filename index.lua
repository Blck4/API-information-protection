require 'resty.core.regex'


local _M = {}


--预处理JSON
function _M.JsonMachine(str)
	local cjson = require('cjson')
	str = cjson.decode(str)
	if not str then
		return nil
	else
		return str
	end
end


--预处理后的还原JSON
function _M.JsonPackag(str)
	local cjson = require('cjson')
	str = cjson.encode(str)
	if not str then
		return nil
	else
		return str
	end
end
 
--有效省级地址码
local provinceCode = {
    11, 12, 13, 14, 15,
    21, 22, 23,
    31, 32, 33, 34, 35, 36, 37, 71,
    41, 42, 43,
    44, 45, 46, 81, 82,
    51, 52, 53, 54, 50,
    61, 62, 63, 64, 65
}
 
--校验码（身份证最后一位）根据前面十七位数字码，按照ISO7064:1983.MOD11-2校验码计算出来的校验码。
local checkCode = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
local mappedCode = {"1", "0", "x", "9", "8", "7", "6", "5", "4", "3", "2"}
 
 
--格式检测
function isFormatOk(id)
    if string.match(id, "%d+") == id or string.match(id, "%d+x") == id then
        return true
    else
        return false
    end
end
 
--地址检测
function isAddressOk(id)
    --省
    local province = tonumber(id:sub(1,2))
    local isProvinceOk = false
    for _,v in ipairs(provinceCode) do
        if province == v then
            isProvinceOk = true
            break
        end
    end
    --市
    local city = tonumber(id:sub(3,4))
    local isCityOk = false
    if city >= 1 and city <= 70 then
        isCityOk = true
    end
    --县
    local county = tonumber(id:sub(5,6))
    local isCountyOk = false
    if (county >= 1 and county <= 18) or (county >= 21 and county <= 99) then
        isCountyOk = true
    end
 
    if isProvinceOk and isCityOk and isCountyOk then
        return true
    else
        return false
    end
end
 
--出生日期检测
function isBirthdayOk(id)
    local y = tonumber(id:sub(7,10))
    local m = tonumber(id:sub(11,12))
    local d = tonumber(id:sub(13,14))
    local date = {year = y, month = m, day = d}
    local t = os.time(date)
    local revertDate = os.date("*t",t)
    if revertDate.year == date.year and revertDate.month == date.month and revertDate.day == date.day then
        return true
    else
        return false
    end
end
 
--校验码检测
function isCheckCodeOk(id)
    local preId = id:sub(1,17)
    local nums = {}
    for c in preId:gmatch(".") do
        table.insert(nums,tonumber(c))
    end
    local sum = 0
    for i,v in ipairs(nums) do
        sum = sum + v * checkCode[i]
    end
    if mappedCode[(sum%11+1)] == id:sub(18, 18) then
        return true
    else
        return false
    end
end


--脱敏身份证
function _M.IDCard(id)
	if #id ~= 18 then
        return id
    end
    if not isFormatOk(id) then
        return id
    end
    if not isAddressOk(id) then
        return id
    end
    if not isBirthdayOk(id) then
        return id
    end
    if not isCheckCodeOk(id) then
        return id
    end
	local obscured_IDCard = string.gsub(id, "(%d%d%d%d)%d%d%d%d%d%d%d%d%d%d", "%1***************")
	if obscured_IDCard then
		return obscured_IDCard
	end  
end


--脱敏邮箱
function _M.Email(str)
	if not str then
		return false
	end
	local regex = "[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?"
	local res, err = string.match(str,regex)
	if res then
		local username, domain = res:sub(1, res:find('@') - 1), res:sub(res:find('@') + 1)
		local obscured_username = username:sub(1, 1) .. string.rep('*', username:len() - 1)
		local obscured_Email = obscured_username .. domain
		return obscured_Email
	end
end


--脱敏手机号码
function _M.Iphone(str)
	if #str ~= 11 then
		return false
	end
	local regex = "[1][3,4,5,7,8]%d%d%d%d%d%d%d%d%d"
	local res, err = string.match(str, regex)
	if res then
		local obscured_phone = string.gsub(str, "(%d%d%d%d)%d%d%d%d%d%d", "%1******")
		return obscured_phone
	end
end
	
--HTTP转发
function _M.HtppRequest(url)
	local http = require('resty.http')
	local httpc = http.new()  
	local res,err = httpc:request_uri(url,{method = "GET",keepalive_timeout=3000})
	if not res then
		return nil
	else
		return res.body
	end
end

--检测敏感信息和脱敏
function _M.Sensitive(v)
    if not v then
		return false
	end
	if type(v) == "string" then
		local result  = _M.Iphone(v)
		if result  then return result end
		result = _M.Email(v)
		if result then return result end
		result = _M.IDCard(v)
		if result then return result end
	end
end


--检测tables敏感信息和脱敏
function _M.table_Sensitive(v)
    if not v then
		return false
	end
	for _,vaule in ipairs(v) do
		if type(vaule) == "string" then
			local result  = _M.Iphone(vaule)
			if result  then return result end
			result = _M.Email(vaule)
			if result then return result end
			result = _M.IDCard(vaule)
			if result then return result end
		end
	end
end
	
	

--主要逻辑函数
function _M.Main()
	local res = _M.HtppRequest("http://192.168.x.x:8080/json/")
	local jsondata  = _M.JsonMachine(res)
	for k,v in pairs(jsondata) do
		if type(v) == "table" then
			for i, item in ipairs(v) do
			local tabvalue = _M.table_Sensitive(item)
			jsondata[i] = tabvalue
			end
		else
			local value = _M.Sensitive(v)
			jsondata[k] = value
		end
	end
	local out = _M.JsonPackag(jsondata)
	ngx.say(out)
end

return _M
