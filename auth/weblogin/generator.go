package weblogin

import (
	logger "ImaginaryCraftManager/log"
	"crypto/sha256"
	"fmt"
	"github.com/go-ini/ini"
	"math/rand"
)

// 生成随机字符串
func generateRandomString(length int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	//rand.Seed(time.Now().UnixNano())
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func getSha256(bytes []byte) string {
	return fmt.Sprintf("%X", sha256.Sum256(bytes))
}

func GenLoginToken(filePath string) {
	username := generateRandomString(16)
	password := generateRandomString(16)
	rconPassword := generateRandomString(16)

	// 创建INI文件
	cfg := ini.Empty()
	section, err := cfg.NewSection("User")
	if err != nil {
		logger.Fatalf("创建失败: %v", err)
	}

	err = section.ReflectFrom(&struct{ Username string }{username})
	if err != nil {
		return
	}
	err = section.ReflectFrom(&struct{ Password string }{password})
	if err != nil {
		return
	}
	err = section.ReflectFrom(&struct{ Rcon_Password string }{rconPassword})
	if err != nil {
		return
	}

	err = cfg.SaveTo(filePath)
	if err != nil {
		logger.Fatalf("INI保存失败: %v", err)
	}
	//fmt.Println(username, password)
}
