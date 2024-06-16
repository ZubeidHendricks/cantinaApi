package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func generateToken() {
	// Generate 32 random bytes
	secretBytes := make([]byte, 32)
	_, err := rand.Read(secretBytes)
	if err != nil {
		fmt.Println("Error generating random bytes:", err)
		return
	}

	// Encode random bytes to a base64 string
	jwtSecret := base64.URLEncoding.EncodeToString(secretBytes)
	fmt.Println("Generated JWT secret:", jwtSecret)
}
