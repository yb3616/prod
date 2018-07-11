package main

import (
	"fmt"
	"github.com/casbin/casbin"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func newAuthorizer(e *casbin.Enforcer) gin.HandlerFunc {
	return func(c *gin.Context) {
		var name string
		if err := sessions.Default(c).Get("uid"); err != nil {
			name = fmt.Sprintf("u%d", err)
		} else {
			name = "u0"
		}
		path := c.Request.URL.Path
		method := c.Request.Method

		if !e.Enforce(name, path, method) {
			c.JSON(403, gin.H{
				"msg": "Unauthorized",
			})
			c.Abort()
		}

		c.Next()
	}
}
