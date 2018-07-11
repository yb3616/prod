package main

import (
	"fmt"
	"github.com/casbin/casbin"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

func addUser(db *gorm.DB, e *casbin.Enforcer, isAdmin bool) func(*gin.Context) {
	type User struct {
		gorm.Model
		UserName string `json:"user_name" binding:"min=4"`
		NickName string `json:"nick_name" binding:"omitempty,min=4"`
		Password string `json:"password" binding:"min=6"`
		Email    string `json:"email" binding:"email" gorm:"-"`
		Phone    string `json:"phone" binding:"len=11,numeric" gorm:"-"`
	}

	return func(c *gin.Context) {
		var user User
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusOK, gin.H{"error": err.Error()})
			return
		}

		// 事务
		tx := db.Begin()
		var err error
		user.Password, err = hashPassword(user.Password)
		if err != nil {
			fmt.Println("密码加密失败")
			return
		}
		if err = tx.Create(&user).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusOK, gin.H{"error": err})
			return
		}
		if err = tx.Create(&Phone{PhoneNumber: user.Phone, UserId: user.ID}).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusOK, gin.H{"error": err})
			return
		}
		if err = tx.Create(&Email{EmailAddress: user.Email, UserId: user.ID}).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusOK, gin.H{"error": err})
			return
		}
		var gid string
		if isAdmin {
			gid = "r1"
		} else {
			gid = "r3"
		}
		e.AddGroupingPolicy(fmt.Sprintf("u%d", user.ID), gid)

		tx.Commit()
		c.JSON(http.StatusOK, gin.H{"msg": "success"})
	}
}

func addAdmin(db *gorm.DB, e *casbin.Enforcer) {
	type User struct {
		gorm.Model
		UserName string `json:"user_name" binding:"min=4"`
		NickName string `json:"nick_name" binding:"omitempty,min=4"`
		Password string `json:"password" binding:"min=6"`
		Email    string `json:"email" binding:"email" gorm:"-"`
		Phone    string `json:"phone" binding:"len=11,numeric" gorm:"-"`
	}

	var user User
	if err := db.Select("id").Table("users").Where(&User{UserName: "admin"}).First(&user).Error; err != nil {
		fmt.Println(err)
	}

	if user.ID != 0 {
		return
	}

	user = User{
		UserName: "admin",
		NickName: "系统管理员",
		Password: "123123",
		Email:    "yb3616@126.com",
		Phone:    "17336293616",
	}

	// 事务
	tx := db.Begin()
	var err error
	user.Password, err = hashPassword(user.Password)
	if err != nil {
		fmt.Println("密码加密失败")
		return
	}
	if err = tx.Create(&user).Error; err != nil {
		tx.Rollback()
		return
	}
	if err = tx.Create(&Phone{PhoneNumber: user.Phone, UserId: user.ID}).Error; err != nil {
		tx.Rollback()
		return
	}
	if err = tx.Create(&Email{EmailAddress: user.Email, UserId: user.ID}).Error; err != nil {
		tx.Rollback()
		return
	}
	gid := "r1"
	e.AddGroupingPolicy(fmt.Sprintf("u%d", user.ID), gid)

	tx.Commit()
}

func createAdmin(db *gorm.DB, e *casbin.Enforcer) func(*gin.Context) {
	return addUser(db, e, true)
}

func createUser(db *gorm.DB, e *casbin.Enforcer) func(*gin.Context) {
	return addUser(db, e, false)
}

func login(db *gorm.DB) func(*gin.Context) {
	type Login struct {
		Email    string `json:"email" binding:"omitempty,email"`
		Phone    string `json:"phone" binding:"omitempty,len=11,numeric"`
		UserName string `json:"user_name" binding:"omitempty,min=4"`
		Password string `json:"password" binding:"required,min=6"`
	}
	return func(c *gin.Context) {
		var user Login
		var result struct {
			Id       uint
			Password string
			UserName string
		}
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusOK, gin.H{"error": err.Error()})
			return
		}

		// 查询数据
		if user.UserName != "" {
			db.Table("users").Select("id,password,user_name").Where("user_name = ?", user.UserName).First(&result)
		} else if user.Email != "" {
			db.Table("users").Select("users.id,users.password,users.user_name").Where("emails.email_address = ?", user.Email).Joins("left join emails on emails.user_id = users.id").First(&result)
		} else if user.Phone != "" {
			db.Table("users").Select("users.id,users.password,users.user_name").Where("phones.phone_number = ?", user.Phone).Joins("left join phones on phones.user_id = users.id").First(&result)
		} else {
			c.JSON(http.StatusOK, gin.H{"error": "no loginid"})
			return
		}

		if user.Password == "" || !checkPassword(user.Password, result.Password) {
			// 登录失败
			c.JSON(http.StatusOK, gin.H{"error": "login failed"})
			return
		}

		// Session 持久化
		session := sessions.Default(c)
		session.Set("uid", result.Id)
		session.Set("user_name", result.UserName)
		if err := session.Save(); err != nil {
			c.JSON(http.StatusOK, gin.H{"error": err})
			return
		}

		// 登录成功
		c.JSON(http.StatusOK, gin.H{"msg": "success"})
	}
}

func getUserInfo(db *gorm.DB, e *casbin.Enforcer) func(*gin.Context) {
	type Result struct {
		ID           uint
		UserName     string
		NickName     string
		EmailAddress string
		PhoneNumber  string
		Roles        []string
	}
	return func(c *gin.Context) {
		var result Result
		session := sessions.Default(c)
		uid := session.Get("uid").(uint)
		if err := db.Table("users").Select("users.id, users.user_name, users.nick_name, emails.email_address, phones.phone_number").Where("users.id = ?", uid).Joins("left join emails on emails.user_id = users.id").Joins("left join phones on phones.user_id = users.id").First(&result).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"err": err.Error()})
			return
		}
		result.Roles = e.GetRolesForUser(fmt.Sprintf("u%d", uid))
		c.JSON(http.StatusOK, gin.H{
			"msg":    "success",
			"result": result,
		})
	}
}

func getUsers(db *gorm.DB) func(*gin.Context) {
	type User struct {
		ID       uint
		UserName string
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
		if err := db.Offset(page.Start - 1).Limit(page.Lines).Find(&users).Error; err != nil {
			c.JSON(http.StatusOK, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"msg":  "success",
			"data": users,
		})
	}
}

func logout(c *gin.Context) {
	s := sessions.Default(c)
	s.Clear()
	s.Save()
	c.JSON(http.StatusOK, gin.H{
		"msg": "success",
	})
}

// 加密
func hashPassword(pwd string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	return string(bytes), err
}

// 解密
func checkPassword(pwd, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pwd))
	return err == nil
}
