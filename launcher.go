package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func existingDNSProbe(origin string) bool {
	client := &http.Client{Timeout: 500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := client.Get(origin + "/api/health")
	if err != nil {
		return false
	}
	defer r.Body.Close()
	var v struct {
		App string `json:"app"`
	}
	return r.StatusCode == 200 && json.NewDecoder(r.Body).Decode(&v) == nil && v.App == "DNSProbe"
}
func openBrowser(origin string) {
	if os.Getenv("DNSPROBE_NO_BROWSER") != "" {
		return
	}
	if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", origin).Start(); err != nil {
		fmt.Println("Откройте в браузере:", origin, "Ошибка запуска:", err)
	}
}
