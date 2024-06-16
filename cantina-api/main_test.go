// main_test.go
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupRouter() *gin.Engine {
	db, _ = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	db.AutoMigrate(&User{}, &Dish{}, &Drink{})

	router := gin.Default()
	router.POST("/register", registerUser)
	router.POST("/login", rateLimiterMiddleware(), loginUser)

	auth := router.Group("/")
	auth.Use(authMiddleware())
	{
		auth.POST("/dishes", createDish)
		auth.GET("/dishes/:id", getDish)
		auth.GET("/dishes", listDishes)
		auth.PUT("/dishes/:id", updateDish)
		auth.DELETE("/dishes/:id", deleteDish)

		auth.POST("/drinks", createDrink)
		auth.GET("/drinks/:id", getDrink)
		auth.GET("/drinks", listDrinks)
		auth.PUT("/drinks/:id", updateDrink)
		auth.DELETE("/drinks/:id", deleteDrink)
	}

	return router
}

func hashPasswordForTest(password string) string {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(hashedPassword)
}

func TestRegisterUser(t *testing.T) {
	router := setupRouter()

	user := User{
		Name:     "Test User",
		Email:    "test@example.com",
		Password: "password",
	}

	w := httptest.NewRecorder()
	body, _ := json.Marshal(user)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(body))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "User registered successfully")
}

func TestLoginUser(t *testing.T) {
	router := setupRouter()

	// Register user first
	user := User{
		Name:     "Test User",
		Email:    "test@example.com",
		Password: "password",
	}
	user.Password = hashPasswordForTest(user.Password)
	db.Create(&user)

	creds := map[string]string{
		"email":    "test@example.com",
		"password": "password",
	}

	w := httptest.NewRecorder()
	body, _ := json.Marshal(creds)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "token")
}

func TestCreateDish(t *testing.T) {
	router := setupRouter()

	// Register and login user first
	user := User{
		Name:     "Test User",
		Email:    "test@example.com",
		Password: "password",
	}
	user.Password = hashPasswordForTest(user.Password)
	db.Create(&user)

	creds := map[string]string{
		"email":    "test@example.com",
		"password": "password",
	}
	w := httptest.NewRecorder()
	body, _ := json.Marshal(creds)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
	router.ServeHTTP(w, req)

	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	token := response["token"]

	// Create dish
	dish := Dish{
		Name:        "Test Dish",
		Description: "Test Description",
		Price:       10.5,
		Image:       "test.jpg",
	}

	w = httptest.NewRecorder()
	body, _ = json.Marshal(dish)
	req, _ = http.NewRequest("POST", "/dishes", bytes.NewBuffer(body))
	req.Header.Set("Authorization", token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Test Dish")
}

func TestRateLimiter(t *testing.T) {
	router := setupRouter()

	// Register user first
	user := User{
		Name:     "Test User",
		Email:    "test@example.com",
		Password: "password",
	}
	user.Password = hashPasswordForTest(user.Password)
	db.Create(&user)

	creds := map[string]string{
		"email":    "test@example.com",
		"password": "password",
	}

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		body, _ := json.Marshal(creds)
		req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
		router.ServeHTTP(w, req)
		if i < 3 {
			assert.Equal(t, http.StatusOK, w.Code)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, w.Code)
		}
		time.Sleep(500 * time.Millisecond) // Short delay to avoid triggering rate limiter immediately
	}
}
