package main

import (
	"fmt"
	"os"
	"time"

	"test/token"

	"github.com/golang-jwt/jwt/v4"
)

func main() {
	privateKey, err := os.ReadFile("cert/test")
	if err != nil {
		fmt.Printf("Error reading private key file: %v\n", err)
		return
	}

	publicKey, err := os.ReadFile("cert/test.pub")
	if err != nil {
		fmt.Printf("Error reading public key file: %v\n", err)
		return
	}
	claims := jwt.MapClaims{
		"name": "John Doe",
		"role": "admin",
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
	}

	jwtToken := token.NewJWT(privateKey, publicKey)

	token, err := jwtToken.Generate(claims)
	if err != nil {

	}
	fmt.Println("Token: ", token)

	claims, err = jwtToken.Validate(token)
	if err != nil {
		fmt.Printf("Error validating JWT: %v\n", err)
		return
	}

	fmt.Printf("Verified JWT claims: %v\n", claims)

}
