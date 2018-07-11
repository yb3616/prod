package main

import (
	"github.com/casbin/casbin"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
)

func route(r *gin.Engine, db *gorm.DB, e *casbin.Enforcer) {
	// 路由
	r.POST("/admin/role", createRole(db))
	r.DELETE("/admin/role/:rid", deleteRole(db))
	r.PUT("/admin/role/:rid", editRoles(db))
	r.GET("/admin/role", getRoles(db))

	r.POST("/admin/user_role", createUserRole(e))
    r.DELETE("/admin/user_role/:rid/:uid", deleteUserRole(e))
	r.GET("/admin/user_role", getUserRole(db, e))

    r.POST("/admin/sub_obj", createSubObj(e))
    r.DELETE("/admin/sub_obj", deleteSubObj(e))
    r.PUT("/admin/sub_obj", putSubObj(e))
    r.GET("/admin/sub_obj", getSubObj(db, e))

	r.GET("/admin/user", getUsers(db))

    r.GET("/admin/user2", getUsersInfo(db, e))
    r.PUT("/admin/user2", updateUser(db))

	r.POST("/admin/logon", createAdmin(db, e))
	r.GET("/user/info", getUserInfo(db, e))
	r.POST("/logon", createUser(db, e))
	r.POST("/login", login(db))
	r.GET("/logout", logout)
}
