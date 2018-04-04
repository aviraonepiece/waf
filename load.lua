--waf core load
require 'config'

--Load WAF rule
function get_rule(rule_file_name)
    local io = require 'io'
    local RULE_PATH = config_rule_dir --将config中的路径赋值
    local RULE_FILE = io.open(RULE_PATH..'/'..rule_file_name,"r") --只读模式
    if RULE_FILE == nil then
        return
    end
    RULE_TABLE = {}  --声明一个表，把读取的规则放在表里，返回
    for line in RULE_FILE:lines() do
        table.insert(RULE_TABLE,line)
    end
    RULE_FILE:close()
    return(RULE_TABLE)
end

--LOad the client IP
function get_client_ip()
    CLIENT_IP = ngx.req.get_headers()["X_real_ip"] --获取客户IP的常见做法，先real_ip，再X_forward_for
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.req.get_headers()["X_Forwarded_For"]
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = ngx.var.remote_addr
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = ""
    end
    return CLIENT_IP
end

--Load the client user agent --获取UA信息，没有就为空
function get_user_agent()
    USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
       USER_AGENT = ""
    end
    return USER_AGENT
end



--return logs
function log_record(method,url,data,ruletag)
    local cjson = require("cjson")  --c语言习惯的json，跨平台
    local io = require 'io'
    local LOG_PATH = config_log_dir
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = get_user_agent()
    local SERVER_NAME = ngx.var.server_name
    local LOCAL_TIME = ngx.localtime()
    local log_json_obj = {                    --json的logs内容
                 client_ip = CLIENT_IP,
                 local_time = LOCAL_TIME,
                 server_name = SERVER_NAME,
                 user_agent = USER_AGENT,
                 attack_method = method,
                 match_url = url,
                 match_data = data,
                 match_rule = ruletag,
              }
    local LOG_RESULT = cjson.encode(log_json_obj)  --格式化为cjson
    local LOG_NAME = LOG_PATH..'/'..ngx.today().."_waf.log"
    local file = io.open(LOG_NAME,"a")
    if file == nil then
        return
    end
    file:write(LOG_RESULT.."\n")
    file:flush()
    file:close()
end

--WAF return  --返回结果
function waf_output()
    if config_waf_output == "redirect" then
        ngx.redirect(config_waf_redirect_url, 301) --301跳转到你的url，我这里用的是后者
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(config_output_html)   --html在config里自己定义
        ngx.exit(ngx.status)
    end
end

