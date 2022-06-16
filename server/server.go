package server

import (
	"encoding/json"
	"errors"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

var now = time.Now

func setTimeForTest(t time.Time) {
	now = func() time.Time { return t }
}

type Status int

const (
	Unspecified Status = iota
	Active
	Deleted
)

func (s Status) String() string {
	switch s {
	case Active:
		return "active"
	case Deleted:
		return "deleted"
	}
	return ""
}

func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

type UserDetails struct {
	Email             string `json:"email"`
	Name              string `json:"name,omitempty"`
	ProfilePictureURL string `json:"profile_picture_url,omitempty"`
	Status            Status `json:"status,omitempty"`
	FirstName         string `json:"first_name,omitempty"`
	LastName          string `json:"last_name,omitempty"`
}

type OrganizationDetails struct {
	Name    string   `json:"name"`
	Status  Status   `json:"status,omitempty"`
	Members []string `json:"members,omitempty"`
}

type ClientAuthTokenData struct {
	UserID              string
	OrganizationID      string
	UserDetails         *UserDetails
	OrganizationDetails *OrganizationDetails
}

func ClientAuthToken(appID string, secret []byte, data ClientAuthTokenData) (string, error) {
	if data.UserID == "" {
		return "", errors.New("missing UserID")
	}
	if data.OrganizationID == "" {
		return "", errors.New("missing OrganizationID")
	}
	claims := jwt.MapClaims{
		"app_id":          appID,
		"iat":             now().Unix(),
		"exp":             now().Add(1 * time.Minute).Unix(),
		"user_id":         data.UserID,
		"organization_id": data.OrganizationID,
	}
	if data.UserDetails != nil {
		if data.UserDetails.Email == "" {
			return "", errors.New("missing required user field: Email")
		}
		claims["user_details"] = data.UserDetails
	}
	if data.OrganizationDetails != nil {
		if data.OrganizationDetails.Name == "" {
			return "", errors.New("missing required organization field: Name")
		}
		claims["organization_details"] = data.OrganizationDetails
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ServerAuthToken(appID string, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"app_id": appID,
		"iat":    now().Unix(),
		"exp":    now().Add(1 * time.Minute).Unix(),
	})
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
