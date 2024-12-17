package auth

import (
	"github.com/dgrijalva/jwt-go"
	"time"
	"fmt"
	"github.com/Users/natza/userServer/model"
)

var secretKey = []byte("your-secret-key")

// Генерація JWT токена
func GenerateJWT(user model.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

// Валідація JWT токена
func ValidateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	return token, err
}
