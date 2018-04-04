require 'fuctions'

function waf_main()
    if white_ip_check() then                       --先检查是不是IP白名单，不是就给后面处理
    elseif black_ip_check() then                   --再检查是不是黑名单，不是就给后面处理
    elseif cc_attack_check() then                  --判断是不是cc攻击，不是就给后面处理
    elseif user_agent_attack_check() then           --判断UA有没有不干净的东西，没有就给后面处理
    elseif cookie_attack_check() then               --判断cookie有没有不干净的，没有就给后面处理
    elseif white_url_check() then                   --看看符不符合白名url，不符合接着匹配
    elseif url_attack_check() then                   --看看有没有不该让访问的目录，没有就接着匹配
    elseif url_args_attack_check() then            --看看get请求的参数是不是干净的，干净的话接着匹配
    elseif post_attack_check() then              --最后看看post的内容有没有恶意请求
    else
        return
    end
end

waf_main()

