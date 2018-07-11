package main

import (
	"github.com/casbin/casbin"
)

func policyInit(e *casbin.Enforcer) {
	e.AddPolicy("r1", "/*", "(POST)|(DELETE)|(PUT)|(GET)", "allow")        // 第一角色默认为系统管理员角色，拥有所有权限
	e.AddPolicy("r1", "/login", "(POST)|(DELETE)|(PUT)|(GET)", "deny")     // 第一角色默认为系统管理员角色，禁止登录功能
	e.AddPolicy("r1", "/logon", "(POST)|(DELETE)|(PUT)|(GET)", "deny")     // 第一角色默认为系统管理员角色，禁止注册功能
	e.AddPolicy("r2", "/logon", "POST", "allow") // 未登录用户具有注册权限
	e.AddPolicy("r2", "/login", "POST", "allow") // 未登录用户具有登录权限
	e.AddPolicy("*", "/logout", "(POST)|(DELETE)|(PUT)|(GET)", "allow")    // 已登录用户具有注销权限
	e.AddPolicy("r2", "/logout", "(POST)|(DELETE)|(PUT)|(GET)", "deny")    // 未登录用户没有注销权限
	e.AddPolicy("r3", "/user/*", "(POST)|(DELETE)|(PUT)|(GET)", "allow")   // 已登录用户具有/user/*所有权限
	e.AddGroupingPolicy("u0", "r2")              // anonymous; uid=0; rid=2
	e.AddGroupingPolicy("u1", "r3")              // anonymous; uid=0; rid=2
}
