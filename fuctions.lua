--WAF fuctions
require 'config'
require 'load'

--args
local rulematch = ngx.re.find 
--ngx.re.find返回的是匹配的字串的起始位置索引和结束位置索引，否则，将会返回两个nil
local unescape = ngx.unescape_uri
--将urlencode的字符转码为标准字符

--check post
function post_attack_check() --和检查url参数一样
	if config_post_filter == "on" then
		ngx.req.read_body()
		local POST_RULES = get_rules('post.rule')
		for _, rule in pairs(POST_RULES) do
			local POST_ARGS = ngx.req.get_post_args() or {}
			for _, data in pairs(POST_ARGS) do
				if type(data) == "table" then
					post_data = table.concat(data, " ")
				else
					post_data = data
				end
				if rule ~= "" and rulematch(post_data, rule, "j") then
					record_log('post_attack', post_data, "-", rule)
					if config_waf_enable == "on" then
						waf_output()
						return true
					end
				end
			end
		end
	end
	return false
end
--allow white ip
function white_ip_check()
     if config_white_ip_check == "on" then
        local WHITE_IP_RULE = get_rule('whiteip.rule') -- 加载规则
        local WHITE_IP = get_client_ip()
        if WHITE_IP_RULE ~= nil then    -- ~=是不等于的意思
            for _,rule in pairs(WHITE_IP_RULE) do      
                -- pairs是迭代函数，_和rule作为状态常量和控制变量的值作为参数被调用
                if rule ~= "" and rulematch(WHITE_IP,rule,"j") then 
                    -- j 无意义
                    record_log('White_IP',ngx.var_request_uri,"_","_")
                    return true
                end
            end
        end
    end
end

--CHECK black ip
function black_ip_check()
     if config_black_ip_check == "on" then
        local BLACK_IP_RULE = get_rule('blackip.rule')
        local BLACK_IP = get_client_ip() --调用load里的函数加载rule中的黑名单
        if BLACK_IP_RULE ~= nil then --如果黑名单不为空
            for _,rule in pairs(BLACK_IP_RULE) do
                if rule ~= "" and rulematch(BLACK_IP,rule,"j") then
                    record_log('BlackList_IP',ngx.var_request_uri,"_","_") --调用load种的日志记录
                    if config_waf_enable == "on" then
                        ngx.exit(403) --返回403错误，如果没开启waf就不返回
                        return true
                    end
                end
            end
        end
    end
end

--allow white url
function white_url_check()
    if config_white_url_check == "on" then
        local URL_WHITE_RULES = get_rule('writeurl.rule')
        local GOAT_URL = ngx.var.request_uri --加载url白名单
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(GOAT_URL,rule,"j") then
                    return true  --有的话就放过呗
                end
            end
        end
    end
end

--check url args，
function url_args_attack_check() --这是重头戏
    if config_url_args_check == "on" then
        local ARGS_RULES = get_rule('args.rule') --加载规则
        for _,rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            for key, val in pairs(REQ_ARGS) do   --迭代检查
                if type(val) == 'table' then
                    ARGS_DATA = table.concat(val, " ")  --如果表中包含
                else
                    ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),rule,"j") then
                    record_log('BLock_URL_Args',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end


--CHECK cc attack
function cc_attack_check()
    if config_cc_check == "on" then
        local ATTCKURI=ngx.var.uri
        local CC_TOKEN = get_client_ip()..ATTCKURI --获取恶意IP
        local limitcheck = ngx.shared.limit
        CCcount=tonumber(string.match(config_cc_rate,'(.*)/'))
        CCseconds=tonumber(string.match(config_cc_rate,'/(.*)'))  --tonumbr用于数据类型转换
        local req,_ = limitcheck:get(CC_TOKEN)
        if req then       --如果确有其事
            if req > CCcount then
                record_log('CC_Attack',ngx.var.request_uri,"-","-")
                if config_waf_enable == "on" then
                    ngx.exit(403)
                end
            else
                limitcheck:incr(CC_TOKEN,1)
            end
        else
            limitcheck:set(CC_TOKEN,1,CCseconds)
        end
    end
    return false
end

--check cookie
function cookie_attack_check()
    if config_cookie_check == "on" then
        local COOKIE_RULES = get_rule('cookie.rule') --获取规则
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _,rule in pairs(COOKIE_RULES) do     --迭代检查cooike
                if rule ~="" and rulematch(USER_COOKIE,rule,"j") then
                    record_log('Block_Cookie',ngx.var.request_uri,"-",rule) --锁定并输出日志
                    if config_waf_enable == "on" then
                        waf_output()  --开着的话就输出
                        return true
                    end
                end
             end
	    end
    end
    return false
end

--check url
function url_attack_check()
    if config_url_check == "on" then
        local URL_RULES = get_rule('url.rule') --放置不该访问的目录
        local GOAT_URL = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(GOAT_URL,rule,"j") then
                record_log('Block_URL',GOAT_URL,"-",rule)
                if config_waf_enable == "on" then  --如果开着就是输出
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end


--UA检查
function user_agent_attack_check()
    if config_user_agent_check == "on" then
        local USER_AGENT_RULES = get_rule('useragent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"j") then
                    log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end
