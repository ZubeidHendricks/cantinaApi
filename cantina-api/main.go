package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	_ "net/http/pprof"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	db                *gorm.DB
	err               error
	jwtKey            = []byte("")
	redisClient       *redis.Client
	ctx               = context.Background()
	cacheTimeout      = 5 * time.Minute
	log               = logrus.New()
	oauthConfig       *oauth2.Config
	googleOauthConfig *oauth2.Config
	stateString       = "randomString"
)

type User struct {
	ID       uint   `json:"id" gorm:"primaryKey"`
	Name     string `json:"name"`
	Email    string `json:"email" gorm:"unique"`
	Password string `json:"-"`
}

type Dish struct {
	ID          uint    `json:"id" gorm:"primaryKey"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
	Image       string  `json:"image"`
}

type Drink struct {
	ID          uint    `json:"id" gorm:"primaryKey"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
	Image       string  `json:"image"`
}

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

type Review struct {
	ID      uint   `json:"id" gorm:"primaryKey"`
	UserID  uint   `json:"user_id"`
	DishID  uint   `json:"dish_id"`
	DrinkID uint   `json:"drink_id"`
	Rating  int    `json:"rating"`
	Comment string `json:"comment"`
}

type ReviewDetail struct {
	ID      uint   `json:"id"`
	UserID  uint   `json:"user_id"`
	User    string `json:"user"`
	DishID  uint   `json:"dish_id"`
	Dish    string `json:"dish"`
	DrinkID uint   `json:"drink_id"`
	Drink   string `json:"drink"`
	Rating  int    `json:"rating"`
	Comment string `json:"comment"`
}
type ReviewResponse struct {
	ID      uint   `json:"id"`
	User    string `json:"user"`
	Dish    string `json:"dish"`
	Drink   string `json:"drink"`
	Rating  int    `json:"rating"`
	Comment string `json:"comment"`
}

func main() {
	// Database setup
	db, err = gorm.Open(sqlite.Open("tfg.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	// Profiling setup
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// Initialize logrus
	log.Formatter = new(logrus.JSONFormatter)
	log.Level = logrus.InfoLevel

	db.AutoMigrate(&User{}, &Dish{}, &Drink{}, &Review{})
	setupIndexes(db)

	// Redis setup
	redisClient = redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Redis server address
	})

	// OAuth2 setup
	oauthConfig = &oauth2.Config{

		RedirectURL: "http://localhost:8080/auth/github/callback",
		Scopes:      []string{"user:email"},
		Endpoint:    github.Endpoint,
	}

	googleOauthConfig = &oauth2.Config{

		RedirectURL: "http://localhost:8080/auth/google/callback",
		Scopes:      []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:    google.Endpoint,
	}

	// Gin setup
	router := gin.Default()
	router.Use(gzip.Gzip(gzip.DefaultCompression))
	// Serve the HTML template
	router.LoadHTMLGlob("templates/*")
	// Endpoint to serve the dashboard HTML page
	router.GET("/dashboard", func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", nil)
	})

	// Auth routes
	router.POST("/register", registerUser)
	router.POST("/login", rateLimiterMiddleware(), loginUser)
	router.GET("/auth/github", githubLogin)
	router.GET("/auth/github/callback", githubCallback)
	router.GET("/auth/google", googleLogin)
	router.GET("/auth/google/callback", googleCallback)
	router.GET("/api/dashboard", createDashboard)

	// Dish routes (protected)
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

	router.Run(":8080")
}

func setupIndexes(db *gorm.DB) {
	db.Exec("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_dishes_name ON dishes(name)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_drinks_name ON drinks(name)")
}

func rateLimiterMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := "rate_limiter_" + c.ClientIP()
		if err := redisClient.Incr(ctx, key).Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Rate limiter failed"})
			c.Abort()
			return
		}

		redisClient.Expire(ctx, key, time.Minute)

		count, err := redisClient.Get(ctx, key).Int()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Rate limiter failed"})
			c.Abort()
			return
		}

		if count > 60 { // Limit to 60 requests per minute
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func registerUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to bind user JSON")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to hash password")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = hashedPassword

	if err := db.Create(&user).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to create user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	log.WithFields(logrus.Fields{
		"user_id": user.ID,
	}).Info("User registered")
	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

func loginUser(c *gin.Context) {
	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&creds); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to bind login JSON")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := db.Where("email = ?", creds.Email).First(&user).Error; err != nil {
		log.WithFields(logrus.Fields{
			"email": creds.Email,
		}).Warn("Invalid email or password")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	if !checkPasswordHash(creds.Password, user.Password) {
		log.WithFields(logrus.Fields{
			"email": creds.Email,
		}).Warn("Invalid email or password")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Email: user.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to create token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}

	log.WithFields(logrus.Fields{
		"user_id": user.ID,
	}).Info("User logged in")
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			log.Warn("Authorization header required")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			log.WithFields(logrus.Fields{
				"error": err,
			}).Warn("Invalid token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("email", claims.Email)
		c.Next()
	}
}

func createDish(c *gin.Context) {
	var dish Dish
	if err := c.ShouldBindJSON(&dish); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to bind dish JSON")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.Create(&dish).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to create dish")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create dish"})
		return
	}

	log.WithFields(logrus.Fields{
		"dish_id": dish.ID,
	}).Info("Dish created")
	c.JSON(http.StatusOK, gin.H{"message": "Dish created successfully", "dish": dish})
}

func getDish(c *gin.Context) {
	id := c.Param("id")
	var dish Dish

	// Check cache first
	cacheKey := "dish_" + id
	cachedDish, err := redisClient.Get(ctx, cacheKey).Result()
	if err == redis.Nil {
		if err := db.First(&dish, id).Error; err != nil {
			log.WithFields(logrus.Fields{
				"error":   err.Error(),
				"dish_id": id,
			}).Error("Failed to get dish")
			c.JSON(http.StatusNotFound, gin.H{"error": "Dish not found"})
			return
		}

		// Cache the dish
		dishJSON, _ := json.Marshal(dish)
		redisClient.Set(ctx, cacheKey, dishJSON, cacheTimeout)
	} else if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to get dish from cache")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get dish"})
		return
	} else {
		json.Unmarshal([]byte(cachedDish), &dish)
	}

	log.WithFields(logrus.Fields{
		"dish_id": dish.ID,
	}).Info("Dish retrieved")
	c.JSON(http.StatusOK, dish)
}

func listDishes(c *gin.Context) {
	var dishes []Dish
	if err := db.Find(&dishes).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to list dishes")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list dishes"})
		return
	}

	log.Info("Dishes listed")
	c.JSON(http.StatusOK, dishes)
}

func updateDish(c *gin.Context) {
	id := c.Param("id")
	var dish Dish

	if err := db.First(&dish, id).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error":   err.Error(),
			"dish_id": id,
		}).Error("Failed to find dish")
		c.JSON(http.StatusNotFound, gin.H{"error": "Dish not found"})
		return
	}

	if err := c.ShouldBindJSON(&dish); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to bind dish JSON")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.Save(&dish).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to update dish")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update dish"})
		return
	}

	// Invalidate cache
	cacheKey := "dish_" + id
	redisClient.Del(ctx, cacheKey)

	log.WithFields(logrus.Fields{
		"dish_id": dish.ID,
	}).Info("Dish updated")
	c.JSON(http.StatusOK, gin.H{"message": "Dish updated successfully", "dish": dish})
}

func deleteDish(c *gin.Context) {
	id := c.Param("id")
	if err := db.Delete(&Dish{}, id).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error":   err.Error(),
			"dish_id": id,
		}).Error("Failed to delete dish")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete dish"})
		return
	}

	// Invalidate cache
	cacheKey := "dish_" + id
	redisClient.Del(ctx, cacheKey)

	log.WithFields(logrus.Fields{
		"dish_id": id,
	}).Info("Dish deleted")
	c.JSON(http.StatusOK, gin.H{"message": "Dish deleted successfully"})
}

func createDrink(c *gin.Context) {
	var drink Drink
	if err := c.ShouldBindJSON(&drink); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to bind drink JSON")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.Create(&drink).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to create drink")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create drink"})
		return
	}

	log.WithFields(logrus.Fields{
		"drink_id": drink.ID,
	}).Info("Drink created")
	c.JSON(http.StatusOK, gin.H{"message": "Drink created successfully", "drink": drink})
}

func getDrink(c *gin.Context) {
	id := c.Param("id")
	var drink Drink

	// Check cache first
	cacheKey := "drink_" + id
	cachedDrink, err := redisClient.Get(ctx, cacheKey).Result()
	if err == redis.Nil {
		if err := db.First(&drink, id).Error; err != nil {
			log.WithFields(logrus.Fields{
				"error":    err.Error(),
				"drink_id": id,
			}).Error("Failed to get drink")
			c.JSON(http.StatusNotFound, gin.H{"error": "Drink not found"})
			return
		}

		// Cache the drink
		drinkJSON, _ := json.Marshal(drink)
		redisClient.Set(ctx, cacheKey, drinkJSON, cacheTimeout)
	} else if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to get drink from cache")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get drink"})
		return
	} else {
		json.Unmarshal([]byte(cachedDrink), &drink)
	}

	log.WithFields(logrus.Fields{
		"drink_id": drink.ID,
	}).Info("Drink retrieved")
	c.JSON(http.StatusOK, drink)
}

func listDrinks(c *gin.Context) {
	var drinks []Drink
	if err := db.Find(&drinks).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to list drinks")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list drinks"})
		return
	}

	log.Info("Drinks listed")
	c.JSON(http.StatusOK, drinks)
}

func updateDrink(c *gin.Context) {
	id := c.Param("id")
	var drink Drink

	if err := db.First(&drink, id).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error":    err.Error(),
			"drink_id": id,
		}).Error("Failed to find drink")
		c.JSON(http.StatusNotFound, gin.H{"error": "Drink not found"})
		return
	}

	if err := c.ShouldBindJSON(&drink); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to bind drink JSON")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.Save(&drink).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to update drink")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update drink"})
		return
	}

	// Invalidate cache
	cacheKey := "drink_" + id
	redisClient.Del(ctx, cacheKey)

	log.WithFields(logrus.Fields{
		"drink_id": drink.ID,
	}).Info("Drink updated")
	c.JSON(http.StatusOK, gin.H{"message": "Drink updated successfully", "drink": drink})
}

func deleteDrink(c *gin.Context) {
	id := c.Param("id")
	if err := db.Delete(&Drink{}, id).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error":    err.Error(),
			"drink_id": id,
		}).Error("Failed to delete drink")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete drink"})
		return
	}

	// Invalidate cache
	cacheKey := "drink_" + id
	redisClient.Del(ctx, cacheKey)

	log.WithFields(logrus.Fields{
		"drink_id": id,
	}).Info("Drink deleted")
	c.JSON(http.StatusOK, gin.H{"message": "Drink deleted successfully"})
}

func githubLogin(c *gin.Context) {
	url := oauthConfig.AuthCodeURL(stateString)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func githubCallback(c *gin.Context) {
	if c.Query("state") != stateString {
		log.Warn("Invalid OAuth state")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OAuth state"})
		return
	}

	token, err := oauthConfig.Exchange(ctx, c.Query("code"))
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to exchange token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
		return
	}

	client := oauthConfig.Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to get user info")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}
	defer resp.Body.Close()

	var emails []struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to decode user info")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode user info"})
		return
	}

	if len(emails) == 0 {
		log.Warn("No email found for the user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No email found for the user"})
		return
	}

	email := emails[0].Email
	tokenString, err := createToken(email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func googleLogin(c *gin.Context) {
	url := googleOauthConfig.AuthCodeURL(stateString)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func googleCallback(c *gin.Context) {
	if c.Query("state") != stateString {
		log.Warn("Invalid OAuth state")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OAuth state"})
		return
	}

	token, err := googleOauthConfig.Exchange(ctx, c.Query("code"))
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to exchange token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
		return
	}

	client := googleOauthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo?alt=json")
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to get user info")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to decode user info")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode user info"})
		return
	}

	tokenString, err := createToken(userInfo.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func createToken(email string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to create token")
		return "", err
	}

	log.WithFields(logrus.Fields{
		"email": email,
	}).Info("Token created")
	return tokenString, nil
}

func createReview(c *gin.Context) {
	var review Review
	if err := c.ShouldBindJSON(&review); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to bind review JSON")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.Create(&review).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to create review")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create review"})
		return
	}

	log.WithFields(logrus.Fields{
		"review_id": review.ID,
	}).Info("Review created")
	c.JSON(http.StatusOK, gin.H{"message": "Review created successfully", "review": review})
}

func getReview(c *gin.Context) {
	id := c.Param("id")
	var review Review

	if err := db.First(&review, id).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error":     err.Error(),
			"review_id": id,
		}).Error("Failed to get review")
		c.JSON(http.StatusNotFound, gin.H{"error": "Review not found"})
		return
	}

	log.WithFields(logrus.Fields{
		"review_id": review.ID,
	}).Info("Review retrieved")
	c.JSON(http.StatusOK, review)
}

func listReviews(c *gin.Context) {
	var reviews []Review
	if err := db.Find(&reviews).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to list reviews")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list reviews"})
		return
	}

	log.Info("Reviews listed")
	c.JSON(http.StatusOK, reviews)
}

func updateReview(c *gin.Context) {
	id := c.Param("id")
	var review Review

	if err := db.First(&review, id).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error":     err.Error(),
			"review_id": id,
		}).Error("Failed to find review")
		c.JSON(http.StatusNotFound, gin.H{"error": "Review not found"})
		return
	}

	if err := c.ShouldBindJSON(&review); err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to bind review JSON")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.Save(&review).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Failed to update review")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update review"})
		return
	}

	log.WithFields(logrus.Fields{
		"review_id": review.ID,
	}).Info("Review updated")
	c.JSON(http.StatusOK, gin.H{"message": "Review updated successfully", "review": review})
}

func deleteReview(c *gin.Context) {
	id := c.Param("id")
	if err := db.Delete(&Review{}, id).Error; err != nil {
		log.WithFields(logrus.Fields{
			"error":     err.Error(),
			"review_id": id,
		}).Error("Failed to delete review")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete review"})
		return
	}

	log.WithFields(logrus.Fields{
		"review_id": id,
	}).Info("Review deleted")
	c.JSON(http.StatusOK, gin.H{"message": "Review deleted successfully"})
}

func createDashboard(c *gin.Context) {
	var reviews []Review
	if err := db.Preload("User").Preload("Dish").Preload("Drink").Find(&reviews).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type ReviewResponse struct {
		ID      uint   `json:"id"`
		User    string `json:"user"`
		Dish    string `json:"dish"`
		Drink   string `json:"drink"`
		Rating  int    `json:"rating"`
		Comment string `json:"comment"`
	}

	var reviewResponses []ReviewResponse
	for _, review := range reviews {
		var user User
		var dish Dish
		var drink Drink
		db.First(&user, review.UserID)
		db.First(&dish, review.DishID)
		db.First(&drink, review.DrinkID)

		reviewResponses = append(reviewResponses, ReviewResponse{
			ID:      review.ID,
			User:    user.Name,
			Dish:    dish.Name,
			Drink:   drink.Name,
			Rating:  review.Rating,
			Comment: review.Comment,
		})
	}

	c.JSON(http.StatusOK, gin.H{"reviews": reviewResponses})
}
