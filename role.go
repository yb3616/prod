package main

import (
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"net/http"
	"strconv"
)

func createRole(db *gorm.DB) func(*gin.Context) {
	type RoleInfo struct {
		RoleName string `json:"role_name" binding:"required"`
	}

	return func(c *gin.Context) {
		var role RoleInfo
		if err := c.BindJSON(&role); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		result := Role{
			RoleName: role.RoleName,
		}
		if err := addRole(db, &result); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"error": err,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"msg": "success",
			"rid": result.ID,
		})
	}
}

func addRole(db *gorm.DB, role *Role) error {
	return db.Create(role).Error
}

func getRoles(db *gorm.DB) func(*gin.Context) {
	return func(c *gin.Context) {
		var page Pager
		if err := c.BindQuery(&page); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var roles []Role
		if page.Lines < 0 {
			page.Start = -1
		}
		if err := db.Table("roles").Offset(page.Start - 1).Limit(page.Lines).Find(&roles).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"err": err})
			return
		}
		var total int
		if err := db.Table("roles").Count(&total).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"err": err})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"msg":   "success",
			"roles": roles,
			"total": total,
		})
	}
}

func editRoles(db *gorm.DB) func(*gin.Context) {
	type RoleInfo struct {
		RoleName string `json:"role_name" binding:"required"`
	}
	return func(c *gin.Context) {
		var (
			role RoleInfo
			err  error
			id   uint64
		)

		if err := c.BindJSON(&role); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if id, err = strconv.ParseUint(c.Param("rid"), 10, 0); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		result := Role{
			ID:       uint(id),
			RoleName: role.RoleName,
		}

		if err := db.Save(&result).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"msg": "success"})
	}
}

func deleteRole(db *gorm.DB) func(*gin.Context) {
	return func(c *gin.Context) {
		var (
			id  uint64
			err error
		)
		if id, err = strconv.ParseUint(c.Param("rid"), 10, 0); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		item := Role{
			ID: uint(id),
		}

		if err := db.Delete(&item).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"msg": "success"})
	}
}
