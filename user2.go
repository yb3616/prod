package main

import (
	"fmt"
	"github.com/casbin/casbin"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"net/http"
	"strconv"
	"time"
)

func getUsersInfo(db *gorm.DB, e *casbin.Enforcer) func(*gin.Context) {
	type User struct {
		ID           uint
		DeletedAt    *time.Time
		UserName     string
		NickName     string
		EmailAddress string
		PhoneNumber  string
		Roles        []string
	}
	return func(c *gin.Context) {
		var page Pager
		if err := c.BindQuery(&page); err != nil {
			c.JSON(http.StatusOK, gin.H{"error": err.Error()})
			return
		}
		if page.Lines < 0 {
			page.Start = -1
		}

		var users []User
		if err := db.Unscoped().Select("users.id, users.deleted_at, users.user_name, users.nick_name, emails.email_address, phones.phone_number").Joins("left join emails on emails.user_id = users.id").Joins("left join phones on phones.user_id = users.id").Offset(page.Start - 1).Limit(page.Lines).Find(&users).Error; nil != err {
			c.JSON(http.StatusOK, gin.H{"err": err.Error()})
			return
		}
		var total int
		if err := db.Table("users").Select("users.id").Joins("left join emails on emails.user_id = users.id").Joins("left join phones on phones.user_id = users.id").Count(&total).Error; nil != err {
			c.JSON(http.StatusOK, gin.H{"err": err.Error()})
			return
		}
		for k, v := range users {
			users[k].Roles = e.GetRolesForUser(fmt.Sprintf("u%d", v.ID))
			for m, n := range users[k].Roles {
				if rid, err := strconv.ParseInt(n[1:], 10, 0); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
					return
				} else {
					role := Role{ID: uint(rid)}
					if err := db.First(&role).Error; err != nil {
						c.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
						return
					}
					users[k].Roles[m] = role.RoleName
				}
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"msg":   "success",
			"value": users,
			"total": total,
		})
	}
}

func updateUser(db *gorm.DB) func(*gin.Context) {
	type User struct {
		ID           uint       `json:"ID" binding:"required"`
		DeletedAt    *time.Time `json:"DeletedAt"`
		UpdatedAt    *time.Time `binding:"-"`
		UserName     string     `json:"UserName" binding:"min=4"`
		NickName     string     `json:"NickName" binding:"omitempty,min=4"`
		EmailAddress string     `json:"EmailAddress" binding:"email" gorm:"-"`
		PhoneNumber  string     `json:"PhoneNumber" binding:"len=11,numeric" gorm:"-"`
		Password     string     `json:"Password" binding:"omitempty,min=6"`
	}
	return func(c *gin.Context) {
		var user User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusOK, gin.H{"err1": err.Error()})
			return
		}

		tx := db.Begin()
		// 更新Email关系
		email := Email{
			UserId: user.ID,
		}
		if err := tx.Where(&email).First(&email).Error; nil != err {
			c.JSON(http.StatusBadRequest, gin.H{"err2": err.Error()})
			return
		}
		if email.EmailAddress != user.EmailAddress {
			if err := tx.Where(&email).Delete(&email).Error; nil != err {
				tx.Rollback()
				c.JSON(http.StatusOK, gin.H{"err3": err.Error()})
				return
			}
			email.UserId = user.ID
			email.EmailAddress = user.EmailAddress
			if err := tx.Create(&email).Error; nil != err {
				tx.Rollback()
				c.JSON(http.StatusOK, gin.H{"err4": err.Error()})
				return
			}
		}
		// 更新Phone关系
		phone := Phone{
			UserId: user.ID,
		}
		if err := tx.Where(&phone).First(&phone).Error; nil != err {
			c.JSON(http.StatusBadRequest, gin.H{"err5": err.Error()})
			return
		}
		if phone.PhoneNumber != user.PhoneNumber {
			if err := tx.Where(&phone).Delete(&phone).Error; nil != err {
				tx.Rollback()
				c.JSON(http.StatusOK, gin.H{"err6": err.Error()})
				return
			}
			phone.UserId = user.ID
			phone.PhoneNumber = user.PhoneNumber
			if err := tx.Create(&phone).Error; nil != err {
				tx.Rollback()
				c.JSON(http.StatusOK, gin.H{"err7": err.Error()})
				return
			}
		}
		// 添加修改时间为当前时间
		nw := time.Now()
		user.UpdatedAt = &nw
		fmt.Println(user.DeletedAt, user.Password)

		// 加密密码，若存在的话
		if "" != user.Password {
			user.Password, _ = hashPassword(user.Password)
		} else {
			var pwd User
			if err := tx.Table("users").Unscoped().Select("password").Where("id = ?", user.ID).First(&pwd).Error; nil != err {
				tx.Rollback()
				c.JSON(http.StatusOK, gin.H{"err8": err.Error()})
				return
			}
			user.Password = pwd.Password
		}

		// 软删除
		if nil != user.DeletedAt {
			user.UpdatedAt = &nw
		}

		if err := tx.Table("users").Unscoped().Save(&user).Error; nil != err {
			tx.Rollback()
			c.JSON(http.StatusOK, gin.H{"err9": err.Error()})
			return
		}

		tx.Commit()
		c.JSON(http.StatusOK, gin.H{"msg": "success"})
	}
}
