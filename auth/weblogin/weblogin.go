package weblogin

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-ini/ini"
)

var users = map[string]string{}

func RefreshUsers(filePath string) {
	_ = os.Remove(filePath)
	GenLoginToken(filePath)
}

func GetUsername(filePath string) string {
	var username string
	for key := range users {
		username = key
	}
	return username
}

func LoadUsers(filePath string) {
	cfg, err := ini.Load(filePath)
	if err != nil {
		fmt.Println("无ini文件，生成中……")
		GenLoginToken(filePath)
		LoadUsers(filePath)
		return
	}

	section := cfg.Section("User")
	if section == nil {
		fmt.Println("section读取失败，ini重新生成中……")
		_ = os.Remove(filePath)
		GenLoginToken(filePath)
		LoadUsers(filePath)
		return
	}

	users = make(map[string]string)
	username := section.Key("Username").String()
	password := section.Key("Password").String()
	users[username] = getSha256([]byte(password))
	fmt.Println(users)
}

func CheckLogin(storedUser, storedPassword string) bool {
	return storedPassword == users[storedUser] && storedPassword != "" && storedUser != ""
}

// CheckIsLogined 检查用户是否已经登录的中间件
func CheckIsLogined(r *http.Request) bool {
	cookie, err := r.Cookie("session")
	//fmt.Println(r.Cookies())
	if err != nil || cookie.Value == "" || users[cookie.Value] == "" {
		return false
	}
	return true
}
