#!/bin/sh

#添加角色
#curl -X POST -H 'Content-type:application/json' http://localhost:80/admin/role -d '{"role_name":"administrator"}'
#curl -X POST -H 'Content-type:application/json' http://localhost:80/admin/role -d '{"role_name":"anonymous"}'
#curl -X POST -H 'Content-type:application/json' http://localhost:80/admin/role -d '{"role_name":"user"}'
baseURL='http://localhost:8080'

# 注册
curl -X POST -H 'Content-type:application/json' $baseURL/logon -d '{"user_name":"normal","password":"123123","email":"yb3616@sina.com","phone":"13333333333"}'

# 登录
curl -X POST -H 'Content-type:application/json' -c "./data/login.session" -b "./data/login.session" $baseURL/login -d '{"user_name":"admin","password":"123123"}'
curl -X POST -H 'Content-type:application/json' -c "./data/login.session" -b "./data/login.session" $baseURL/login -d '{"email":"yb3616@qq.com","password":"123123"}'
curl -X POST -H 'Content-type:application/json' -c "./data/login.session" -b "./data/login.session" $baseURL/login -d '{"phone":"17336293616","password":"123123"}'
