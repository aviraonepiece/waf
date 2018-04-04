
# 这是一个基于lua和nginx的waf


nginx的配置文件开发起来很麻烦也不优雅，这里用lua进行扩充，在此感谢[loveshell](https://github.com/loveshell/ngx_lua_waf) 提供思路和[openresty](https://github.com/agentzh)ngx_lua集成，本waf有更清晰、精简的实现方法和供理解的注释，大量扩充了规则库里的正则表达式。顺便学习lua语言，实践证明学起来很快，非常好上手。

环境部署采用了openresty1.9.3.2和兼容性强的ubuntu14.04。

## 原理：
    1. 每个worker（工作进程）创建一个Lua VM，worker内所有协程共享VM；
    2. 将Nginx I/O原语封装后注入 Lua VM，允许Lua代码直接访问；
    3. 每个外部请求都由一个Lua协程处理，协程之间数据隔离；
    4. Lua代码调用I/O操作等异步接口时，会挂起当前协程（并保护上下文数据），而不阻塞worker；
    5. I/O等异步操作完成时还原相关协程上下文数据，并继续运行；

## ngx_lua的API以及介绍：
 - [详细看我的个人博客](http://notesus.cn/?p=234)

## 功能及优点：

总结起来就是全功能的http头检查：    
-   防止sql注入，本地包含，部分溢出，fuzzing测试，命令执行，xss等web攻击 （通过检查url参数、post等参数实现）
-   防止数据库备份之类文件泄漏（通过检查用户url实现）
-   防止常见的测压攻击、cc攻击 （通过检查请求频率实现）
-   屏蔽常见的扫描黑客工具，扫描器 （通过检查UA实现）
-   屏蔽异常的网络请求 （通过请求频率、黑白名单实现）
-   防止webshell上传 （通过检查post敏感内容实现）

## 文件说明：
- process.lua waf功能检查顺序文件
- config.lua  waf开关以及配置，注释英语很好懂，on为开，off为关
- fuctions.lua waf的各项参数的检查函数
- load.lua     waf的功能流程以及用户参数获取

## 不足之处：
- 要合理把握好log文件目录权限，否则用户故意构造含webshell的请求，容易文件包含从logs提权
- 规则是静态的，除非实时更新，否则迟早被绕过
- **维护用正则表达式构成的规则比较繁琐，后面参看我机器学习实现的waf，对，就是这么膨胀，先立下flag，部署有想法了，日后实现。除了数据打标繁琐外、每次更新功能时，再次训练一下模型，让机器自己识别，岂不美哉？**

## 部署(我用的是ubuntu14.04，其他的自测)：
比较繁琐，花了两天时间终于摸索出来了，很开心🌝
既然这里面安装openresty，之前先要彻底删除nginx，因为openresty自带nginx。
```
sudo apt-get--purge remove nginx
sudo apt-get autoremove
ps -ef|grep nginx
dpkg --get-selections|grep nginx 
sudo apt-get --purge remove nginx//查询上一步操作与nginx有关的软件，删掉
sudo apt-get --purge remove nginx-common
sudo apt-get --purge remove nginx-core
ps -ef |grep nginx//看一下进程，还有就删掉
```
安装依赖包

```
apt-cache serach readline
apt-get install libpcre-dev  libpcrecpp0 libpcre3   //nginx要用它做正则引擎
apt-get install libreadline-dev libreadline6-dev libtinfo-dev
apt-get install openssl libssl-dev perl make build-essential curl   
//openssl做安全引擎
```
下载并编译安装openresty(ngx_openresty-1.9.3.2.tar.gz)
```
 cd /usr/local/src/
 wget https://openresty.org/download/ngx_openresty-1.9.3.2.tar.gz
 tar -zxf ngx_openresty-1.9.3.2.tar.gz
 cd ngx_openresty-1.9.3.2
[root@ ngx_openresty-1.9.3.2] ./configure --prefix=/usr/local/openresty-1.9.3.2 --with-luajit --with-http_stub_status_module --with-pcre --with-pcre-jit
[root@ ngx_openresty-1.9.3.2] make, make install
[root@ ngx_openresty-1.9.3.2]ln -s /usr/local/openresty-1.9.3.2/ /usr/local/openresty
```
测试openresty安装

```
//在/usr/local/openresty/nginx/nginx.conf添加
location /hi {
default_type text/html;
content_by_lua_block{
ngx.say('hello fuckopenrastry')
}
}
```

测试并启动openrestry下的nginx

```
[root@ ngx_openresty-1.9.3.2] /usr/local/openresty/nginx/sbin/nginx -t //文本模式详细信息
nginx: the configuration file /usr/local/openresty-1.9.3.2/nginx/conf/nginx.conf syntax is ok
nginx: configuration file /usr/local/openresty-1.9.3.2/nginx/conf/nginx.conf test is successful

[root@ ngx_openresty-1.9.3.2] pkill nginx //杀死进程
[root@ ngx_openresty-1.9.3.2] /usr/local/openresty/nginx/sbin/nginx/重新启动
```

在github上克隆下代码

```
[root@ ~] git clone https://github.com/aviraonepiece/waf
Cloning into 'waf'...
remote: Counting objects: 75, done.
remote: Total 75 (delta 0), reused 0 (delta 0), pack-reused 75
Unpacking objects: 100% (75/75), done.
[root@ ~]# cp -a ./waf/waf /usr/local/openresty/nginx/conf/
```
修改Nginx的配置文件，加入（http字段）以下配置。注意路径，同时WAF日志默认存放在/tmp/日期_waf.log

```
[root@ ~] vim /usr/local/openresty/nginx/conf/nginx.conf
```
```
#WAF
lua_shared_dict limit 50m; #防cc使用字典，大小50M
lua_package_path /usr/local/openresty/nginx/conf/waf/?.lua; //waf规则
init_by_lua_file /usr/local/openresty/nginx/conf/waf/init.lua; //初始化规则
access_by_lua_file /usr/local/openresty/nginx/conf/waf/access.lua;

[root@ ~] /usr/local/openresty/nginx/sbin/nginx -t
[root@ ~]/usr/local/openresty/nginx/sbin/nginx -s reload  //重新载入更新配置
```


根据日志记录位置，创建日志目录

```
[root@ ~] mkdir /tmp/waf_logs
[root@ ~] chown -R www.www /tmp/waf_logs 
//这里要给此文件夹存放权限，可以暂时使用777权限，原则上要使用nginx的用户组
```
