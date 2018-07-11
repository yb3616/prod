package main

import (
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

// 用户表
type User struct {
	gorm.Model
	UserName string `gorm:"unique_index"`
	NickName string
	Password string `gorm:"not null"`
}

type Role struct {
	ID       uint   `gorm:"primary_key"`
	RoleName string `gorm:"unique_index"`
}

//type UserRole struct {
//	RoleId uint
//	UserId uint
//}

type Phone struct {
	PhoneNumber string `gorm:"unique_index"`
	UserId      uint   `gorm:"unique_index"`
}

type Email struct {
	EmailAddress string `gorm:"unique_index"`
	UserId       uint   `gorm:"unique_index"`
}

func initDB() *gorm.DB {
	// 创建连接
	db, err := gorm.Open("sqlite3", "./data/data.db")
	if err != nil {
		panic("连接数据库失败")
	}

	// 创建表
	if !db.HasTable(&User{}) {
		db.CreateTable(&User{})
		fmt.Println("Create Table: User")
	}
	if !db.HasTable(&Role{}) {
		db.CreateTable(&Role{})
		fmt.Println("Create Table: Role")
	}
	//	if !db.HasTable(&UserRole{}) {
	//		db.CreateTable(&UserRole{})
	//		if db.Model(&UserRole{}).AddUniqueIndex("idx_user_role", "user_id", "role_id").Error != nil {
	//			panic("无法创建唯一索引：user_role")
	//		}
	//		fmt.Println("Create Table: UserRole")
	//	}
	if !db.HasTable(&Phone{}) {
		db.CreateTable(&Phone{})
		fmt.Println("Create Table: Phone")
	}
	if !db.HasTable(&Email{}) {
		db.CreateTable(&Email{})
		fmt.Println("Create Table: Email")
	}

	return db
}
