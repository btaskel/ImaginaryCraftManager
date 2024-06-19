package route

import (
	"ImaginaryCraftManager/auth/weblogin"
	"ImaginaryCraftManager/cmd/app/route/rutils"
	"ImaginaryCraftManager/jsonStructs/requestStructs/authStructs"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func RouteAuth() {
	/* ---------------- web访问控制 ----------------*/
	rg := rutils.NewRouteGroup("auth")
	handlers := rutils.Handlers{
		"login": func(w http.ResponseWriter, r *http.Request) {
			//初始登陆界面
			loginFunc(w, r)
		},
		"logout": func(w http.ResponseWriter, r *http.Request) {
			//登出账号
			if CheckCookie(w, r) {
				return
			}
			logoutfunc(w, r)
		},
		"logout/refresh": func(w http.ResponseWriter, r *http.Request) {
			//刷新账号信息并登出
			if CheckCookie(w, r) {
				return
			}
			refreshLogin(w, r)
		},
	}
	rg.AddRoute(handlers)
}

func loginFunc(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var user authStructs.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "非法请求体", http.StatusBadRequest)
		return
	}

	if weblogin.CheckLogin(user.Username, fmt.Sprintf("%X", sha256.Sum256([]byte(user.Password)))) {
		fmt.Println("登陆成功")
		expiration := time.Now().Add(24 * time.Hour)
		cookie := &http.Cookie{
			Name:    "session",
			Value:   user.Username,
			Expires: expiration,
			Path:    "/",
		}
		http.SetCookie(w, cookie)
		return
	}
	http.Error(w, "账号或者密码错误", http.StatusUnauthorized)
}

func logoutfunc(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:    "session",
		Value:   "",
		Expires: time.Unix(1, 0),
		MaxAge:  -1,
		Path:    "/",
	}
	http.SetCookie(w, cookie)
}

func refreshLogin(w http.ResponseWriter, r *http.Request) {

	cookie := &http.Cookie{
		Name:    "session",
		Value:   "",
		Expires: time.Unix(1, 0),
		MaxAge:  -1,
		Path:    "/",
	}
	http.SetCookie(w, cookie)
	weblogin.RefreshUsers("authorities.ini")
	weblogin.LoadUsers("authorities.ini")
}
