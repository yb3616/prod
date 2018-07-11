package main

import (
	"fmt"
	"github.com/casbin/casbin"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"net/http"
	"strconv"
)

type Pager struct {
	Start int `form:"start" binding:"required"`
	Lines int `form:"lines" binding:"required"`
}

func getUserRole(db *gorm.DB, e *casbin.Enforcer) func(*gin.Context) {
	type User struct {
		ID       uint
		UserName string
	}
	type Policyer struct {
		User struct {
			ID    uint
			Value string
		}
		Role struct {
			ID    uint
			Value string
		}
	}
	return func(c *gin.Context) {
		policys := e.GetGroupingPolicy()
		var (
			results []Policyer
			user    User
			role    Role
			err     error
			id      uint64
		)
		for _, policy := range policys {
			// SUBJECT 1
			var result Policyer
			if "*" == policy[0] {
				result.User.ID = 0
				result.User.Value = "*"
			} else {
				if id, err = strconv.ParseUint(policy[0][1:], 10, 0); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}
				if "u" == policy[0][0:1] {
					user.ID = uint(id)
					if user.ID == 0 {
						result.User.Value = "游客"
					} else {
						if err = db.First(&user).Error; err != nil {
							c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
							return
						}
						result.User.Value = user.UserName
					}
					result.User.ID = user.ID
				} else if "r" == policy[0][0:1] {
					role.ID = uint(id)
					if err = db.First(&role).Error; err != nil {
						c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
						return
					}
					result.User.ID = role.ID
					result.User.Value = role.RoleName
				}
			}

			// SUBJECT 2
			if "*" == policy[1] {
				result.Role.ID = 0
				result.Role.Value = "*"
			} else {
				if id, err = strconv.ParseUint(policy[1][1:], 10, 0); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}
				if "u" == policy[1][0:1] {
					user.ID = uint(id)
					if err = db.First(&user).Error; err != nil {
						c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
						return
					}
					result.User.ID = user.ID
					result.User.Value = user.UserName
				} else if "r" == policy[1][0:1] {
					role.ID = uint(id)
					if err = db.First(&role).Error; err != nil {
						c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
						return
					}
					result.Role.ID = role.ID
					result.Role.Value = role.RoleName
				}
			}

			results = append(results, result)
		}

		c.JSON(http.StatusOK, gin.H{
			"msg":    "success",
			"policy": results,
		})
	}
}

func createUserRole(e *casbin.Enforcer) func(*gin.Context) {
	type UserRoler struct {
		UID  uint   `json:"uid" binding:"required"`
		RIDS []uint `json:"rids" binding:"required"`
	}
	return func(c *gin.Context) {
		var param UserRoler
		if err := c.BindJSON(&param); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		for _, rid := range param.RIDS {
			if !e.AddGroupingPolicy(fmt.Sprintf("u%d", param.UID), fmt.Sprintf("r%d", rid)) {
				c.JSON(http.StatusBadRequest, gin.H{"err": "无法创建映射关系，请重试！"})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"msg": "success"})
	}
}

func deleteUserRole(e *casbin.Enforcer) func(*gin.Context) {
	return func(c *gin.Context) {
		var (
			rid uint64
			uid uint64
			err error
		)
		if rid, err = strconv.ParseUint(c.Param("rid"), 10, 0); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if uid, err = strconv.ParseUint(c.Param("uid"), 10, 0); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if !e.DeleteRoleForUser(fmt.Sprintf("u%d", uid), fmt.Sprintf("r%d", rid)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无法删除该映射，请刷新后重试！"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"msg": "success",
		})
	}
}
