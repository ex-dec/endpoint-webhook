package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type RequestData struct {
	Message string `json:"message"`
}

func getAppToken() string {
	token := os.Getenv("AUTH_TOKEN")
	if token == "" {
		log.Fatal("AUTH_TOKEN not set in .env")
	}
	return token
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	appToken := getAppToken()

	return func(w http.ResponseWriter, r *http.Request) {
		authToken := r.Header.Get("token")

		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body.Close()
		r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

		whitespace := regexp.MustCompile(`\s+`)
		cleanBody := whitespace.ReplaceAllString(string(bodyBytes), " ")

		status := 200
		statusMsg := "Authorized"

		if authToken == "" {
			status = http.StatusForbidden
			statusMsg = "Forbidden: token header missing"
		} else if authToken != appToken {
			status = http.StatusForbidden
			statusMsg = "Forbidden: invalid token"
		}

		log.Printf("[%s] Status: %d | auth_token: %s | app_token: %s | Body: %s",
			time.Now().Format(time.RFC3339), status, authToken, appToken, cleanBody)

		if status != 200 {
			http.Error(w, statusMsg, status)
			return
		}

		next(w, r)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	var data RequestData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		log.Printf("[%s] Status: 400 | Error: invalid JSON", time.Now().Format(time.RFC3339))
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "authorized",
		"message": data.Message,
	})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	logFile, err := os.OpenFile("logs/request.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("Could not open log file: ", err)
	}
	log.SetOutput(logFile)

	http.HandleFunc("/", authMiddleware(handler))
	fmt.Println("Server running at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
