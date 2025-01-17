package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	ginprometheus "github.com/zsais/go-gin-prometheus"

	"github.com/yowenter/claude-ipam/pkg/ipam"
	"github.com/yowenter/claude-ipam/pkg/leader"
	"github.com/yowenter/claude-ipam/pkg/store/etcd"
	"github.com/yowenter/claude-ipam/pkg/types"
)

var buildtime string
var version string

func main() {
	log.Infof("CLAUDE IPAM Server version `%v`, buildtime `%v`", version, buildtime)
	ipam.InitPrometheus()
	ipamServerConf, err := ipam.LoadIpamServerConfig()
	if err != nil {
		panic(err)
	}

	if ipamServerConf.Debug {
		log.SetLevel(log.DebugLevel)
		gin.SetMode(gin.ReleaseMode)
	} else {
		log.SetLevel(log.InfoLevel)
		gin.SetMode(gin.DebugMode)
	}

	r := gin.New()
	r.Use(gin.LoggerWithWriter(gin.DefaultWriter, "/ping"), gin.Recovery())
	p := ginprometheus.NewPrometheus("gin")
	p.Use(r)

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"buildtime": buildtime,
			"version":   version,
			"name":      "claude ipam server",
		})
	})

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "ok",
		})
	})
	ctx := context.TODO()

	etcdConfig := &etcd.EtcdConfig{
		EtcdEndpoints: ipamServerConf.EtcdEndpoints,

		EtcdKeyFile:    ipamServerConf.EtcdKeyFile,
		EtcdCertFile:   ipamServerConf.EtcdCertFile,
		EtcdCACertFile: ipamServerConf.EtcdCACertFile,

		EtcdKey:    ipamServerConf.EtcdKey,
		EtcdCert:   ipamServerConf.EtcdCert,
		EtcdCACert: ipamServerConf.EtcdCACert,
	}
	controller, e := ipam.NewIpamController(ipamServerConf, etcdConfig)
	if e != nil {
		log.Fatalf("NewIpamController failure %v", e)
	}

	// CNI API
	r.POST("/api/ip/require", BasicAuth(ipamServerConf.BasicUser, ipamServerConf.BasicPass), controller.RequireIPHandler)
	r.POST("/api/ip/release", BasicAuth(ipamServerConf.BasicUser, ipamServerConf.BasicPass), controller.ReleaseIPHandler)

	// Node networkd management
	if !ipamServerConf.AutoAssignNodeIPBlock {
		r.GET("/api/admin/node-network", BasicAuth("admin", ipamServerConf.AdminPass), controller.NodeNetworkHandler)
		r.POST("/api/admin/network", BasicAuth("admin", ipamServerConf.AdminPass), controller.CreateNetworkHandler)
		r.POST("/api/admin/iprange", BasicAuth("admin", ipamServerConf.AdminPass), controller.CreateIPRangeHandler)
		r.POST("/api/admin/node", BasicAuth("admin", ipamServerConf.AdminPass), controller.CreateNodeHandler)
	}

	go leader.RunWithLease(
		ctx, &types.ElectionOption{
			Name:          "cluade-ipam-le",
			Namespace:     "kube-system",
			LeaseDuration: time.Second * 60,
		}, func(ctx context.Context) {
			// TODO net controller

			log.Info("leadership start..")
			go controller.MetrcisCollector()
			go controller.GCAllocatingExpiredIps()
			controller.WatchNetwork()

		}, func() {
			log.Info("leadership lost!")
		})

	s := &http.Server{
		Addr:           ":8080",
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	err = s.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

// BasicAuth middleware for Basic Authentication
func BasicAuth(username, passwd string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.Request.Header.Get("Authorization")
		if auth == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			c.Abort()
			return
		}

		// Split the header into scheme and credentials
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || parts[0] != "Basic" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header"})
			c.Abort()
			return
		}

		// Decode the credentials
		payload, err := decodeBase64(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid base64 credentials"})
			c.Abort()
			return
		}

		// Split the payload into username and password
		credentials := strings.SplitN(payload, ":", 2)
		if len(credentials) != 2 || credentials[0] != username || credentials[1] != passwd {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			c.Abort()
			return
		}

		// If authentication is successful, proceed to the next handler
		c.Next()
	}
}

// Helper function to decode base64
func decodeBase64(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	return string(decoded), err
}
