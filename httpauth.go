package httpauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/blueambertech/logging"
	"github.com/blueambertech/secretmanager"
	"github.com/golang-jwt/jwt"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var (
	StandardTokenLife = time.Hour * 1
)

// Authorize is a middleware func that checks a request has a valid JWT before allowing the request to continue
func Authorize(next http.Handler, sm secretmanager.SecretManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, span := logging.Tracer.Start(r.Context(), "httpauth/Authorize")
		defer span.End()
		tokenString, err := getTokenString(r)
		if err != nil {
			httpError(w, "error extracting token", http.StatusUnauthorized, span, err)
			return
		}

		err = verifyJWT(r.Context(), sm, tokenString)
		if err != nil {
			httpError(w, "failed to verify token", http.StatusForbidden, span, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CreateJWT creates a JWT with no claims
func CreateJWT(ctx context.Context, sm secretmanager.SecretManager) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	k, err := getSecretKey(ctx, sm)
	if err != nil {
		return "", err
	}
	tokenString, err := token.SignedString(k)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// CreateJWTWithClaims creates a JWT with additional claims
func CreateJWTWithClaims(ctx context.Context, sm secretmanager.SecretManager, claims map[string]interface{}) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))

	k, err := getSecretKey(ctx, sm)
	if err != nil {
		return "", err
	}
	tokenString, err := token.SignedString(k)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// GetClaimFromRequestToken extracts a claim from a valid JWT token string (auth header) in the supplied request and returns it
func GetClaimFromRequestToken(r *http.Request, sm secretmanager.SecretManager, claim string) (string, error) {
	tokenString, err := getTokenString(r)
	if err != nil {
		return "", err
	}
	return getStringClaimFromToken(r.Context(), sm, tokenString, claim)
}

func getTokenString(r *http.Request) (string, error) {
	tokenHeader := r.Header.Get("Authorization")
	if tokenHeader == "" {
		return "", errors.New("no auth header")
	}

	split := strings.Split(tokenHeader, "Bearer ")
	if len(split) != 2 {
		return "", errors.New("invalid token format")
	}
	return split[1], nil
}

func verifyJWT(ctx context.Context, sm secretmanager.SecretManager, tokenString string) error {
	token, err := jwt.Parse(tokenString, func(_ *jwt.Token) (interface{}, error) {
		return getSecretKey(ctx, sm)
	})
	if err != nil {
		return err
	}
	if !token.Valid {
		return errors.New("token invalid")
	}
	return nil
}

func getStringClaimFromToken(ctx context.Context, sm secretmanager.SecretManager, tokenString, key string) (string, error) {
	token, err := jwt.Parse(tokenString, func(_ *jwt.Token) (interface{}, error) {
		return getSecretKey(ctx, sm)
	})
	if err != nil {
		return "", err
	}
	claims := token.Claims.(jwt.MapClaims)
	if claim, ok := claims[key].(string); ok {
		return claim, nil
	}
	return "", errors.New("could not find claim with this name")
}

func getSecretKey(ctx context.Context, sm secretmanager.SecretManager) ([]byte, error) {
	secretKey, err := sm.Get(ctx, "jwt-auth-token-key")
	if err != nil {
		return nil, err
	}
	switch v := secretKey.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		return nil, errors.New("secret value was an recognised type")
	}
}

func httpError(w http.ResponseWriter, msg string, httpStatus int, span trace.Span, err error) {
	http.Error(w, msg, httpStatus)
	span.RecordError(err)
	span.SetStatus(codes.Error, msg)
}
