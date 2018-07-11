package main

import (
	"github.com/casbin/casbin"
	"github.com/casbin/gorm-adapter"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"golang.org/x/sync/errgroup"
	"log"
	"net/http"
	"time"
)

var (
	g errgroup.Group
)

// 数据库初始化
var db *gorm.DB = initDB()

func router01() http.Handler {

	r := gin.New()

	store := memstore.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	config := cors.DefaultConfig()
	config.AllowCredentials = true
	config.AllowOrigins = []string{"http://127.0.0.1", "http://localhost", "http://127.0.0.1:80", "http://localhost:80"}
	r.Use(cors.New(config))

	a := gormadapter.NewAdapter("sqlite3", "./data/data.db")
	e := casbin.NewEnforcer("./auth/rbac_with_deny_model.conf", a)
	e.EnableLog(false)
	e.LoadPolicy()
	policyInit(e)
	e.SavePolicy()
	r.Use(newAuthorizer(e))

	// 每次运行程序检查Roles表
	var count int
	db.Table("roles").Count(&count)
	if count == 0 {
		tx := db.Begin()
		if err := addRole(tx, &Role{RoleName: "administrator"}); err != nil {
			tx.Rollback()
			panic("error")
		}
		if err := addRole(tx, &Role{RoleName: "anonymous"}); err != nil {
			tx.Rollback()
			panic("error")
		}
		if err := addRole(tx, &Role{RoleName: "user"}); err != nil {
			tx.Rollback()
			panic("error")
		}
		tx.Commit()
	}

	addAdmin(db, e)

	// 路由
	route(r, db, e)

	return r
	//r.Run("127.0.0.1:8080")
}

func router02() http.Handler {
	r := gin.New()
	r.StaticFile("/index.html", "./web/index.html")
    r.Static("/static", "./web/static")
	// r.StaticFile("/static/js/app.06aebbe94344cb7f78b7.js", "./web/static/js/app.06aebbe94344cb7f78b7.js")
	// r.StaticFile("/static/js/manifest.2ae2e69a05c33dfc65f8.js", "./web/static/js/manifest.2ae2e69a05c33dfc65f8.js")
	// r.StaticFile("/static/js/vendor.09ee4d52863f8c06f8f4.js", "./web/static/js/vendor.09ee4d52863f8c06f8f4.js")
	// r.StaticFile("/static/img/iptables.7b6d9cc.png", "./web/static/img/iptables.7b6d9cc.png")
	// r.StaticFile("/static/img/materialdesignicons-webfont.602efac.svg", "./web/static/img/materialdesignicons-webfont.602efac.svg")
	// r.StaticFile("/static/img/policy.71bb613.png", "./web/static/img/policy.71bb613.png")
	// r.StaticFile("/static/img/screenfetch.9b6bcdf.png", "./web/static/img/screenfetch.9b6bcdf.png")
	// r.StaticFile("/static/img/tb_users.f560760.png", "./web/static/img/tb_users.f560760.png")
	// r.StaticFile("/static/img/vps-info.61537c8.png", "./web/static/img/vps-info.61537c8.png")

	r.LoadHTMLFiles("./web/index.html")

	r.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})
	return r
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	server01 := &http.Server{
		Addr:         ":8080",
		Handler:      router01(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	server02 := &http.Server{
		Addr:         ":80",
		Handler:      router02(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	g.Go(func() error {
		return server01.ListenAndServe()
	})

	g.Go(func() error {
		return server02.ListenAndServe()
	})

	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}

	defer db.Close()
}
