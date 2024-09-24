package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const JWT_SIGNING_KEY = "thisismysecretkey"

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

func GenerateJWTToken(username string) (string, error) {
	//Cria a data para dizer que o token foi expirado
	now := time.Now()
	expires := now.Add(time.Second * 15).Unix()
	claims := jwt.MapClaims{
		"sub":     username,
		"expires": expires,
		"cpf_cli": 32729267808,
	}
	//gerar o token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//Assina o token
	return token.SignedString([]byte(JWT_SIGNING_KEY))
}

func ValidateToken(tokenStr string) (jwt.MapClaims, error) {
	//parse
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		//Verifica se usuario o metodo correto
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid Token: %v", token.Header["alg"])
		}
		//Verifica se usou a assinatura correta
		return []byte(JWT_SIGNING_KEY), nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid Token: %v", err)
	}
	//Verificar token validity
	if !token.Valid {
		return nil, fmt.Errorf("invalid Token")
	}
	//Get claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid Token")
	}
	//check expire time
	expValue := claims["expires"].(float64)
	expires := int64(expValue)
	if time.Now().Unix() > expires {
		return nil, fmt.Errorf("token expired")
	}
	return claims, nil
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var loginParams LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginParams)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusBadRequest)
		return
	}
	if loginParams.Username == "jef" && loginParams.Password == "123" {
		token, err := GenerateJWTToken("jef")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		res := LoginResponse{
			Token: token,
		}
		err = json.NewEncoder(w).Encode(&res)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	http.Error(w, "invalid credentials", http.StatusUnauthorized)
}

func SecureHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("You are authenticated"))
}

func PublicHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("everyone can view this endpoint"))
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Api-Token")
		if len(token) == 0 {
			http.Error(w, "not authorized", http.StatusUnauthorized)
			return
		}
		//Validate Token
		claims, err := ValidateToken(token)
		if err != nil {
			http.Error(w, "not authorized", http.StatusUnauthorized)
			return
		}
		fmt.Println(claims)
		next.ServeHTTP(w, r)
	}
}

func main() {
	http.HandleFunc("/api/auth", LoginHandler)
	http.HandleFunc("/api/public", PublicHandler)
	http.HandleFunc("/api/secure", AuthMiddleware(SecureHandler))
	http.ListenAndServe(":3000", nil)
}
