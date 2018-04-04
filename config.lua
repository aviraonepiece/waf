--WAF config file,enable = "on",disable = "off"

--waf status 
config_waf_enable = "on"            --开关
--log dir   
config_log_dir = "/tmp"
--rule setting 
config_rule_dir = "/usr/local/openresty/nginx/conf/waf/rule"
--enable/disable white url          --白名单url
config_white_url_check = "on"
--enable/disable white ip           --白名单ip
config_white_ip_check = "on"
--enable/disable block ip            --黑名单IP
config_black_ip_check = "on"
--enable/disable url filtering      --不允许访问的目录
config_url_check = "on"
--enalbe/disable url args filtering  --url参数
config_url_args_check = "on"
--enable/disable user agent filtering  --ua检查
config_user_agent_check = "on"
--enable/disable cookie deny filtering --cookie检查
config_cookie_check = "on"
--enable/disable cc filtering  --cc攻击
config_cc_check = "on"
--cc rate the xxx of xxx seconds  --cc攻击检查
config_cc_rate = "15/60"
--enable/disable post filtering  --post参数检查
config_post_check = "on"
--config waf output redirect/html  --选择跳转还是返回
config_waf_output = "html"
--if config_waf_output ,setting url
config_waf_redirect_url = "https://www.notesus.cn"
config_output_html=[[
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Content-Language" content="zh-cn" />
<title>web应用防火墙</title>
</head>
<body>
<h1 align="center"> 好好规范访问，不要试图攻击本站哦。
</body>
</html>
]]

