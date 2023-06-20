// Package server provides utility functions to make it easier to integrate Cord
// into your application.
//
// For more information about the Cord-specific terms used here, see the
// concepts documentation at https://docs.cord.com/concepts/.
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

// A Status is the state of a user or organization.
type Status int

const (
	Unspecified Status = iota
	Active
	Deleted // Deleted users or organizations will have authentication attempts refused
)

// String returns the string value of a Status for use in the API
func (s Status) String() string {
	switch s {
	case Active:
		return "active"
	case Deleted:
		return "deleted"
	}
	return ""
}

// MarshalJSON marshals a Status to its text format
func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UserDetails contains the information about a user that needs to be synced to
// Cord.  Any values that are left at their zero value are not sent except
// Email, which is required.
type UserDetails struct {
	Email             string `json:"email"`
	Name              string `json:"name,omitempty"`
	ProfilePictureURL string `json:"profile_picture_url,omitempty"`
	Status            Status `json:"status,omitempty"`
	FirstName         string `json:"first_name,omitempty"`
	LastName          string `json:"last_name,omitempty"`
}

// OrganizationDetails contains the information about an organization that needs
// to be synced to Cord.  Any values that are left at their zero value are not
// sent except Name, which is required.
type OrganizationDetails struct {
	Name    string   `json:"name"`
	Status  Status   `json:"status,omitempty"`
	Members []string `json:"members,omitempty"`
}

// ClientAuthTokenData is the data that can be supplied in a client auth token.
type ClientAuthTokenData struct {
	UserID              string
	OrganizationID      string
	UserDetails         *UserDetails
	OrganizationDetails *OrganizationDetails
}

// ClientAuthToken returns a client auth token suitable for authenticating a
// user to Cord.
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

// ServerAuthToken returns a server auth token suitable for authenticating
// requests to Cord's REST API (see https://docs.cord.com/rest-apis/).
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

// ApplicationManagementAuthToken returns a server side auth token suitable for
// authenticating requests to Cord's Applications REST API (see https://docs.cord.com/rest-apis/).
func ApplicationManagementAuthToken(customerID string, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"customer_id": customerID,
		"iat":    now().Unix(),
		"exp":    now().Add(1 * time.Minute).Unix(),
	})
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}