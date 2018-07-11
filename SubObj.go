package main

import (
	"fmt"
	"github.com/casbin/casbin"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"net/http"
	"strconv"
	"strings"
)

func getSubObj(db *gorm.DB, e *casbin.Enforcer) func(*gin.Context) {
	type User struct {
		ID       uint
		UserName string
		Roles    []Role
	}
	type Policyer struct {
		SubID    uint
		SubValue string
		Obj      string
		Act      string
		Deny     string
	}
	return func(c *gin.Context) {
		policys := e.GetPolicy()
		var (
			user    User
			err     error
			results []Policyer
			id      uint64
			role    Role
		)
		for _, policy := range policys {
			// SUBJECT
			var result Policyer
			if "*" == policy[0] {
				result.SubID = 0
				result.SubValue = "*"
			} else {
				if id, err = strconv.ParseUint(policy[0][1:], 10, 0); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}
				if "u" == policy[0][0:1] {
					user.ID = uint(id)
					if user.ID == 0 {
						result.SubValue = "游客"
					} else {
						if err = db.First(&user).Error; err != nil {
							c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
							return
						}
						result.SubValue = user.UserName
					}
					result.SubID = user.ID
				} else if "r" == policy[0][0:1] {
					role.ID = uint(id)
					if err = db.First(&role).Error; err != nil {
						c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
						return
					}
					result.SubID = role.ID
					result.SubValue = role.RoleName
				}
			}

			// OBJ
			result.Obj = policy[1]

			// Act
			result.Act = policy[2]

			// DENY
			result.Deny = policy[3]

			results = append(results, result)
		}

		c.JSON(http.StatusOK, gin.H{
			"msg":   "success",
			"value": results,
		})
	}
}

func createSubObj(e *casbin.Enforcer) func(*gin.Context) {
	type Policyer struct {
		SubID uint     `json:"SubID" binding:"required"`
		Obj   string   `json:"Obj" binding:"required"`
		ActA  []string `json:"ActA" binding:"required"`
		Deny  string   `json:"Deny" binding:"required"`
	}
	return func(c *gin.Context) {
		var p Policyer
		if err := c.BindJSON(&p); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
			return
		}
		for k, v := range p.ActA {
			p.ActA[k] = "(" + v + ")"
		}
		act := strings.Join(p.ActA, "|")
		if !e.AddPermissionForUser(fmt.Sprintf("r%d", p.SubID), p.Obj, act, p.Deny) {
			c.JSON(http.StatusBadRequest, gin.H{"err": "添加失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"msg": "success",
		})
	}
}

func deleteSubObj(e *casbin.Enforcer) func(*gin.Context) {
	type Policyer struct {
		SubID    uint     `json:"SubID"`
		Obj      string   `json:"Obj" binding:"required"`
		ActA     []string `json:"ActA" binding:"required"`
		Deny     string   `json:"Deny" binding:"required"`
		SubValue string   `json:"SubValue" binding:"required"`
	}
	return func(c *gin.Context) {
		var p Policyer
		if err := c.BindJSON(&p); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
			return
		}
		for k, v := range p.ActA {
			p.ActA[k] = "(" + v + ")"
		}
		act := strings.Join(p.ActA, "|")
		uuid := fmt.Sprintf("r%d", p.SubID)
		if p.SubID == 0 && p.SubValue == "*" {
			uuid = p.SubValue
		}
		if !e.DeletePermissionForUser(uuid, p.Obj, act, p.Deny) {
			c.JSON(http.StatusBadRequest, gin.H{"err": "添加失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"msg": "success",
		})
	}
}

func putSubObj(e *casbin.Enforcer) func(*gin.Context) {
	type Policyer struct {
		SubID    uint     `json:"SubID"`
		SubValue string   `json:"SubValue" binding:"required"`
		Obj      string   `json:"Obj" binding:"required"`
		ActA     []string `json:"ActA" binding:"required"`
		Deny     string   `json:"Deny" binding:"required"`
	}
	return func(c *gin.Context) {
		var p Policyer
		if err := c.BindJSON(&p); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
			return
		}
		for k, v := range p.ActA {
			p.ActA[k] = "(" + v + ")"
		}
		act := strings.Join(p.ActA, "|")
		uuid := fmt.Sprintf("r%d", p.SubID)
		if p.SubID == 0 && p.SubValue == "*" {
			uuid = p.SubValue
		}
		var usr [][]string
		usr = e.GetPermissionsForUser(uuid)
		for _, v := range usr {
			if v[1] == p.Obj {
				if !e.DeletePermissionForUser(uuid, p.Obj, v[2], v[3]) {
					c.JSON(http.StatusBadRequest, gin.H{"err": "删除失败？请重试" + act})
					return
				}
				if !e.AddPermissionForUser(uuid, p.Obj, act, p.Deny) {
					c.JSON(http.StatusBadRequest, gin.H{"err": "删除失败？请重试" + act})
					return
				}
				break
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"msg": "success",
		})
	}
}
