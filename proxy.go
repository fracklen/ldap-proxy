package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/fracklen/ldap-proxy/ldap"
	"github.com/fracklen/ldap-proxy/logger"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"time"
)

var router = mux.NewRouter()
var cookieHandler *securecookie.SecureCookie

var proxies map[string]*ProxyAccess

var config Config
var ldapClient *ldap.LDAPClient
var configFile string
var jlog *logger.JsonLogger
var port string

type ProxyAccess struct {
	Proxy         *httputil.ReverseProxy
	Name          string
	AllowedGroups []string
	Block         []BlockAccess
}

type Config struct {
	Proxies    []ProxyConfig `json:"proxies"`
	Secrets    SecretsConfig `json:"secrets"`
	LdapConfig LDAPConfig    `json:"ldap"`
	Logging    LogConfig     `json:"logging"`
}

type ProxyConfig struct {
	Name          string        `json:"name"`
	Url           string        `json:"url"`
	AllowedGroups []string      `json:"allowed_groups"`
	Block         []BlockAccess `json:"block_access"`
}

type LogConfig struct {
	Brokers []string `json:"brokers"`
	Topic   string   `json:"topic"`
}

type BlockAccess struct {
	Name         string   `json:"name"`
	Method       string   `json:"method"`
	UrlRegexp    string   `json:"url_regexp"`
	QueryRegexp  string   `json:"query_regexp"`
	UnlessGroups []string `json:"unless_groups"`
}

type SecretsConfig struct {
	HashKey  string `json:"hashKey"`
	BlockKey string `json:"blockKey"`
}

type ProxyCookie struct {
	Name   string   `json:"name"`
	Expire int64    `json:"expire"`
	Groups []string `json:"groups"`
	Proxy  string   `json:"proxy"`
}

type LDAPConfig struct {
	Server               string `json:"server"`
	Basedn               string `json:"basedn"`
	Binduser             string `json:"binduser"`
	Bindpass             string `json:"bindpass"`
	Userattribute        string `json:"userattribute"`
	Groupmemberattribute string `json:"groupmemberattribute"`
	Debug                bool   `json:"debug"`
	Insecure             bool   `json:"insecure"`
}

func NewLdapClient(config LDAPConfig) *ldap.LDAPClient {
	return &ldap.LDAPClient{
		Host:               config.Server,
		ServerName:         config.Server,
		Port:               636,
		UseSSL:             true,
		InsecureSkipVerify: false,
		SkipTLS:            false,
		Base:               config.Basedn,
		BindDN:             config.Binduser,
		BindPassword:       config.Bindpass,
		UserFilter:         config.Userattribute,
		GroupFilter:        config.Groupmemberattribute,
		Attributes:         []string{"cn", "dn", "ou", "member", "memberOf"},
	}
}

func init() {
	flag.StringVar(&configFile, "config-file", "/data/config.json", "JSON Config file")
	flag.StringVar(&port, "port", "8080", "Listen port")
	flag.Parse()
}

func main() {
	parseConfig()
	jlog = logger.NewLogger(config.Logging.Brokers, config.Logging.Topic)
	go jlog.Run()
	http.HandleFunc("/", auth_filter)

	router.HandleFunc("/", indexPageHandler)
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/logout", logoutHandler).Methods("POST")
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		indexPageHandler(w, r)
	})
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static/"))))

	err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
	if err != nil {
		panic(err)
	}
}

func parseConfig() {
	plan, _ := ioutil.ReadFile(configFile)
	err := json.Unmarshal(plan, &config)
	if err != nil {
		panic(err)
	}

	for _, proxy := range config.Proxies {
		remote, err := url.Parse(proxy.Url)
		if err != nil {
			panic(err)
		}

		upstream := httputil.NewSingleHostReverseProxy(remote)
		addProxy(&proxy, upstream)
	}

	hashKey, err := base64.StdEncoding.DecodeString(config.Secrets.HashKey)
	if err != nil {
		panic(err)
	}

	blockKey, err := base64.StdEncoding.DecodeString(config.Secrets.BlockKey)
	if err != nil {
		panic(err)
	}

	if config.Secrets.HashKey == "" || config.Secrets.BlockKey == "" {
		hashKey = securecookie.GenerateRandomKey(64)
		blockKey = securecookie.GenerateRandomKey(32)
	}

	cookieHandler = securecookie.New(hashKey, blockKey)

	ldapClient = NewLdapClient(config.LdapConfig)
}

func addProxy(proxy *ProxyConfig, upstream *httputil.ReverseProxy) {
	if proxies == nil {
		proxies = make(map[string]*ProxyAccess)
	}
	pa := &ProxyAccess{
		Name:          proxy.Name,
		Proxy:         upstream,
		AllowedGroups: proxy.AllowedGroups,
		Block:         proxy.Block,
	}
	proxies[proxy.Name] = pa
}

func setRouter(r *mux.Router) {
	router = r
}

func auth_filter(response http.ResponseWriter, request *http.Request) {
	cookie, err := getCookie(request)
	if err != nil {
		router.ServeHTTP(response, request)
		return
	}
	proxy, ok := proxies[cookie.Proxy]
	if !ok {
		jlog.Warn(map[string]interface{}{
			"event":    "Missing",
			"message":  "Proxy reference missing",
			"proxy":    cookie.Proxy,
			"username": cookie.Name,
			"url":      request.URL.Path,
			"method":   request.Method,
		})
		router.ServeHTTP(response, request)
		return
	}
	if request.URL.Path == "/logout" {
		logoutHandler(response, request)
		jlog.Info(map[string]interface{}{
			"event":    "Logout",
			"message":  "User logged out",
			"proxy":    cookie.Proxy,
			"username": cookie.Name,
			"url":      request.URL.Path,
			"method":   request.Method,
		})
		return
	}
	if authorized(proxy, request, cookie) {
		jlog.Info(map[string]interface{}{
			"event":    "Access",
			"message":  "Authorized access",
			"proxy":    cookie.Proxy,
			"username": cookie.Name,
			"url":      request.URL.Path,
			"method":   request.Method,
		})
		proxy.Proxy.ServeHTTP(response, request)
	} else {
		jlog.Warn(map[string]interface{}{
			"event":    "Denied",
			"message":  "Permission denied",
			"proxy":    cookie.Proxy,
			"username": cookie.Name,
			"url":      request.URL.Path,
			"method":   request.Method,
		})
		permissionDeniedHandler(response, request, cookie)
	}
}

type TempData struct {
	Proxies        []string
	Message        string
	DisplayMessage bool
}

func indexPageHandler(response http.ResponseWriter, request *http.Request) {
	t := template.New("some template")       // Create a template.
	t, _ = t.ParseFiles("static/login.html") // Parse template file.
	proxy_names := []string{}
	for _, proxy := range config.Proxies {
		proxy_names = append(proxy_names, proxy.Name)
	}
	message := getMessage(request)
	dm := false
	if message != "" {
		dm = true
		clearMessage(response)
	}

	data := TempData{Proxies: proxy_names, Message: message, DisplayMessage: dm}

	t.ExecuteTemplate(response, "login.html", data) // merge.
}

func permissionDeniedHandler(response http.ResponseWriter, request *http.Request, cookie *ProxyCookie) {
	response.Header().Add("Content-Type", "application/json")
	http.Error(response, "{\"error\": \"Permission denied\"}", 401)
}

func loginHandler(response http.ResponseWriter, request *http.Request) {
	name := request.FormValue("name")
	pass := request.FormValue("password")
	proxy := request.FormValue("proxy")
	redirectTarget := "/"
	if name != "" && pass != "" && proxy != "" {
		succ, _, groups, err := ldapClient.Authenticate(name, pass)
		defer ldapClient.Close()
		if err == nil {
			intersection := intersect(proxies[proxy].AllowedGroups, groups)
			if len(intersection) > 0 {
				jlog.Warn(map[string]interface{}{
					"event":    "Login",
					"message":  "User logged in",
					"proxy":    proxy,
					"username": name,
					"url":      request.URL.Path,
					"method":   request.Method,
				})
				setSession(name, proxy, groups, response)
				redirectTarget = request.Header.Get("Referer")
			} else {
				jlog.Warn(map[string]interface{}{
					"event":          "Denied",
					"message":        "User was denied access",
					"allowed_groups": proxies[proxy].AllowedGroups,
					"user_groups":    groups,
					"proxy":          proxy,
					"username":       name,
					"url":            request.URL.Path,
					"method":         request.Method,
				})
				setMessage("You don't have access to that", response)
			}
		} else {
			jlog.Warn(map[string]interface{}{
				"event":    "LdapError",
				"message":  fmt.Sprintf("Error authenticating: %+v", err),
				"proxy":    proxy,
				"username": name,
				"url":      request.URL.Path,
				"method":   request.Method,
			})
			setMessage("Error authenticating", response)
		}
		if !succ {
			jlog.Warn(map[string]interface{}{
				"event":    "LoginFailed",
				"message":  "Invalid user or password",
				"proxy":    proxy,
				"username": name,
				"url":      request.URL.Path,
				"method":   request.Method,
			})
			setMessage("Invalid user or password", response)
		}
	}
	http.Redirect(response, request, redirectTarget, 302)
}

func logoutHandler(response http.ResponseWriter, request *http.Request) {
	clearSession(response)
	http.Redirect(response, request, "/", 302)
}

func setMessage(msg string, response http.ResponseWriter) {
	value := map[string]string{
		"msg": msg,
	}
	if encoded, err := cookieHandler.Encode("message", value); err == nil {
		cookie := &http.Cookie{
			Name:  "message",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(response, cookie)
	}
}

func getMessage(request *http.Request) (msg string) {
	if cookie, err := request.Cookie("message"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("message", cookie.Value, &cookieValue); err == nil {
			msg = cookieValue["msg"]
		}
	}
	return msg
}

func setSession(userName string, proxy string, groups []string, response http.ResponseWriter) {
	value := &ProxyCookie{
		Name:   userName,
		Proxy:  proxy,
		Expire: getSessionTimeout(),
		Groups: groups,
	}
	if encoded, err := cookieHandler.Encode("session", value); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(response, cookie)
	}
}

func getSessionTimeout() int64 {
	return time.Now().Unix() + 60*60*24
}

func getCookie(request *http.Request) (*ProxyCookie, error) {
	if cookie, err := request.Cookie("session"); err == nil {
		cookieValue := ProxyCookie{}
		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
			if err != nil || cookieValue.Expire < time.Now().Unix() {
				return nil, errors.New("Timeout")
			}
			return &cookieValue, nil
		}
	}
	return nil, errors.New("No valid login")
}

func clearSession(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}

func clearMessage(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "message",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}

func intersect(a, b []string) []string {
	groups := []string{}
	for _, a1 := range a {
		for _, b1 := range b {
			if a1 == b1 {
				groups = append(groups, a1)
			}
		}
	}
	return groups
}

func authorized(proxy *ProxyAccess, request *http.Request, cookie *ProxyCookie) bool {
	for _, block := range proxy.Block {
		intersection := intersect(block.UnlessGroups, cookie.Groups)
		if len(intersection) > 0 {
			continue
		}
		if request.Method != block.Method || block.Method == "" {
			continue
		}

		matched, err := regexp.MatchString(block.UrlRegexp, request.URL.Path)
		if err != nil {
			panic(err)
		}
		if !matched {
			continue
		}
		query_matched, err := regexp.MatchString(block.QueryRegexp, request.URL.RawQuery)
		if err != nil {
			panic(err)
		}
		if !query_matched {
			continue
		}
		return false
	}
	return true
}
