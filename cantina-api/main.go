package main

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    "strconv"
    "sync"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/gin-contrib/gzip"
    "github.com/gin-gonic/gin"
    "github.com/go-redis/redis/v8"
    "golang.org/x/crypto/bcrypt"
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)

var (
    db           *gorm.DB
    err          error
    jwtKey       = []byte("my_secret_key")
    redisClient  *redis.Client
    ctx          = context.Background()
    cacheTimeout = 5 * time.Minute
)

type User struct {
    ID       uint   `json:"id" gorm:"primaryKey"`
    Name     string `json:"name"`
    Email    string `json:"email" gorm:"unique"`
    Password string `json:"-"`
}

type Dish struct {
    ID          uint   `json:"id" gorm:"primaryKey"`
    Name        string `json:"name"`
    Description string `json:"description"`
    Price       float64 `json:"price"`
    Image       string `json:"image"`
}

type Drink struct {
    ID          uint   `json:"id" gorm:"primaryKey"`
    Name        string `json:"name"`
    Description string `json:"description"`
    Price       float64 `json:"price"`
    Image       string `json:"image"`
}

type Claims struct {
    Email string `json:"email"`
    jwt.StandardClaims
}

func main() {
    // Database setup
    db, err = gorm.Open(sqlite.Open("tfg.db"), &gorm.Config{})
    if err != nil {
        log.Fatal(err)
    }

    db.AutoMigrate(&User{}, &Dish{}, &Drink{})
    setupIndexes(db)

    // Redis setup
    redisClient = redis.NewClient(&redis.Options{
        Addr: "localhost:6379", // Redis server address
    })

    // Gin setup
    router := gin.Default()
    router.Use(gzip.Gzip(gzip.DefaultCompression))

    // Auth routes
    router.POST("/register", registerUser)
    router.POST("/login", rateLimiterMiddleware(), loginUser)

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
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    hashedPassword, err := hashPassword(user.Password)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
        return
    }
    user.Password = hashedPassword

    if err := db.Create(&user).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

func loginUser(c *gin.Context) {
    var creds struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }

    if err := c.ShouldBindJSON(&creds); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    var user User
    if err := db.Where("email = ?", creds.Email).First(&user).Error; err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
        return
    }

    if !checkPasswordHash(creds.Password, user.Password) {
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
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")
        if tokenString == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
            c.Abort()
            return
        }

        claims := &Claims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return jwtKey, nil
        })

        if err != nil || !token.Valid {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        c.Set("email", claims.Email)
        c.Next()
    }
}

func getCachedData(key string, dest interface{}) error {
    val, err := redisClient.Get(ctx, key).Result()
    if err != nil {
        return err
    }
    return json.Unmarshal([]byte(val), dest)
}

func setCachedData(key string, data interface{}) error {
    val, err := json.Marshal(data)
    if err != nil {
        return err
    }
    return redisClient.Set(ctx, key, val, cacheTimeout).Err()
}

// Handlers for Dish
func createDish(c *gin.Context) {
    var dish Dish
    if err := c.ShouldBindJSON(&dish); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    db.Create(&dish)
    c.JSON(http.StatusOK, dish)
}

func getDish(c *gin.Context) {
    id := c.Param("id")
    cacheKey := "dish_" + id

    var dish Dish
    if err := getCachedData(cacheKey, &dish); err == nil {
        c.JSON(http.StatusOK, dish)
        return
    }

    if result := db.First(&dish, id); result.Error != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Dish not found"})
        return
    }

    setCachedData(cacheKey, dish)
    c.JSON(http.StatusOK, dish)
}

func listDishes(c *gin.Context) {
    var dishes []Dish
    cacheKey := "dishes_list"

    page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
    pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
    offset := (page - 1) * pageSize

    if err := getCachedData(cacheKey, &dishes); err == nil {
        c.JSON(http.StatusOK, dishes)
        return
    }

    db.Offset(offset).Limit(pageSize).Find(&dishes)
    setCachedData(cacheKey, dishes)
    c.JSON(http.StatusOK, dishes)
}

func updateDish(c *gin.Context) {
    id := c.Param("id")
    var dish Dish
    if result := db.First(&dish, id); result.Error != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Dish not found"})
        return
    }

    if err := c.ShouldBindJSON(&dish); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    db.Save(&dish)
    cacheKey := "dish_" + id
    redisClient.Del(ctx, cacheKey)
    setCachedData(cacheKey, dish)
    c.JSON(http.StatusOK, dish)
}

func deleteDish(c *gin.Context) {
    id := c.Param("id")
    var dish Dish
    if result := db.First(&dish, id); result.Error != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Dish not found"})
        return
    }

    db.Delete(&dish)
    cacheKey := "dish_" + id
    redisClient.Del(ctx, cacheKey)
    redisClient.Del(ctx, "dishes_list")
    c.JSON(http.StatusOK, gin.H{"message": "Dish deleted successfully"})
}

// Handlers for Drink
func createDrink(c *gin.Context) {
    var drink Drink
    if err := c.ShouldBindJSON(&drink); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    db.Create(&drink)
    c.JSON(http.StatusOK, drink)
}

func getDrink(c *gin.Context) {
    id := c.Param("id")
    cacheKey := "drink_" + id

    var drink Drink
    if err := getCachedData(cacheKey, &drink); err == nil {
        c.JSON(http.StatusOK, drink)
        return
    }

    if result := db.First(&drink, id); result.Error != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Drink not found"})
        return
    }

    setCachedData(cacheKey, drink)
    c.JSON(http.StatusOK, drink)
}

func listDrinks(c *gin.Context) {
    var drinks []Drink
    cacheKey := "drinks_list"

    page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
    pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
    offset := (page - 1) * pageSize

    if err := getCachedData(cacheKey, &drinks); err == nil {
        c.JSON(http.StatusOK, drinks)
        return
    }

    db.Offset(offset).Limit(pageSize).Find(&drinks)
    setCachedData(cacheKey, drinks)
    c.JSON(http.StatusOK, drinks)
}

func updateDrink(c *gin.Context) {
    id := c.Param("id")
    var drink Drink
    if result := db.First(&drink, id); result.Error != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Drink not found"})
        return
    }

    if err := c.ShouldBindJSON(&drink); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    db.Save(&drink)
    cacheKey := "drink_" + id
    redisClient.Del(ctx, cacheKey)
    setCachedData(cacheKey, drink)
    c.JSON(http.StatusOK, drink)
}

func deleteDrink(c *gin.Context) {
    id := c.Param("id")
    var drink Drink
    if result := db.First(&drink, id); result.Error != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Drink not found"})
        return
    }

    db.Delete(&drink)
    cacheKey := "drink_" + id
    redisClient.Del(ctx, cacheKey)
    redisClient.Del(ctx, "drinks_list")
    c.JSON(http.StatusOK, gin.H{"message": "Drink deleted successfully"})
}

