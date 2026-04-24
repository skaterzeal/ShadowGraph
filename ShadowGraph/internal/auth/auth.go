package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Claims JWT token payload
type Claims struct {
	Username string `json:"sub"`
	Role     string `json:"role"`
	Exp      int64  `json:"exp"`
}

var jwtSecret []byte

// InitAuth JWT secret'ı ayarlar
func InitAuth(secret string) {
	jwtSecret = []byte(secret)
}

// GenerateToken kullanıcı için JWT token üretir
func GenerateToken(username, role string) (string, error) {
	header := base64url([]byte(`{"alg":"HS256","typ":"JWT"}`))

	claims := Claims{
		Username: username,
		Role:     role,
		Exp:      time.Now().Add(24 * time.Hour).Unix(),
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64url(claimsJSON)

	sigInput := header + "." + payload
	signature := base64url(sign([]byte(sigInput)))

	return sigInput + "." + signature, nil
}

// ValidateToken JWT token'ı doğrular ve Claims döner
func ValidateToken(tokenStr string) (*Claims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("geçersiz token formatı")
	}

	sigInput := parts[0] + "." + parts[1]
	expectedSig := base64url(sign([]byte(sigInput)))

	if parts[2] != expectedSig {
		return nil, fmt.Errorf("imza doğrulanamadı")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload decode hatası")
	}

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("claims parse hatası")
	}

	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token süresi dolmuş")
	}

	return &claims, nil
}

// RequireAuth HTTP middleware — Bearer token kontrolü
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"Authorization header gerekli"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, `{"error":"Bearer token formatı gerekli"}`, http.StatusUnauthorized)
			return
		}

		claims, err := ValidateToken(parts[1])
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusUnauthorized)
			return
		}

		// Claims'i context'e ekle (basitleştirilmiş)
		r.Header.Set("X-User", claims.Username)
		r.Header.Set("X-Role", claims.Role)
		next(w, r)
	}
}

// RequireRole belirli bir rol gerektirir
func RequireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		userRole := r.Header.Get("X-Role")
		if userRole != role && userRole != "admin" {
			http.Error(w, `{"error":"Yetersiz yetki"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func sign(data []byte) []byte {
	h := hmac.New(sha256.New, jwtSecret)
	h.Write(data)
	return h.Sum(nil)
}

func base64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
