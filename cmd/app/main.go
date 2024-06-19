package app

import (
	"ImaginaryCraftManager/auth/weblogin"
	"ImaginaryCraftManager/cmd/app/route"
	logger "ImaginaryCraftManager/log"
)

const (
	// 因为我不确定需要添加到配置哪里，所以就先暂时写到这里了。
	// network
	tlsEnable   = false // 是否启用tls。
	http3Enable = false // 是否启用HTTP3, 不会受tlsEnable的控制, 强制使用TLS。

	// debug
	loggerLevel = "debug" // 日志等级
)

func Main() {
	// 启动日志器
	logger.NewLogger(loggerLevel)

	// 注册路由
	route.RouteApi()
	route.RouteAuth()
	route.RouteControl()
	route.RouteIndex()
	route.RouteFile()
	route.RouteSetting()
	route.RouteStatic()
	route.RouteWeblogic()
	route.RouteWs()

	weblogin.LoadUsers("authorities.ini")

	err := runHTTPServer(serverOption{
		addr:     ":8000",
		certName: "",
		keyName:  "",
		certMode: "",
	})
	if err != nil {
		logger.Fatalf("Main: 运行HTTP服务时错误: %v", err)
	}

	logger.Infoln("running...(*^▽^*)")
}
