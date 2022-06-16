package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var (
	kAppID  = "1234567890"
	kSecret = []byte("0987654321")
	kUserID = "112233"
	kOrgID  = "445566"
)

func init() {
	setTimeForTest(time.Unix(1655383113, 0))
}

func valuesFromToken(token string) map[string]interface{} {
	payload := strings.Split(token, ".")[1]
	payload_decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		panic(err)
	}
	result := map[string]interface{}{}
	if err = json.Unmarshal(payload_decoded, &result); err != nil {
		panic(err)
	}
	return result
}

func TestServerAuthTokenBasics(t *testing.T) {
	token, err := ServerAuthToken(kAppID, kSecret)
	if err != nil {
		t.Fatal(err)
	}
	if token != "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhcHBfaWQiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjU1MzgzMTczLCJpYXQiOjE2NTUzODMxMTN9.tHHEyK1iNNXQefd2Vva6O36MsgfDMmV3aq4YbUTi1tWSTTZr3k7brtgdFKuRIKwJdfn1fOJg-DylL2sRXjPJSA" {
		t.Fatalf("Token generation failed, received %v", token)
	}
}

func TestClientAuthTokenBasics(t *testing.T) {
	token, err := ClientAuthToken(kAppID, kSecret,
		ClientAuthTokenData{
			UserID:         kUserID,
			OrganizationID: kOrgID,
			UserDetails: &UserDetails{
				Email:     "flooey@example.com",
				Name:      "Adam Vartanian",
				FirstName: "Adam",
				LastName:  "Vartanian",
				Status:    Active,
			},
			OrganizationDetails: &OrganizationDetails{
				Name:   "Cord",
				Status: Active,
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	if token != "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhcHBfaWQiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjU1MzgzMTczLCJpYXQiOjE2NTUzODMxMTMsIm9yZ2FuaXphdGlvbl9kZXRhaWxzIjp7Im5hbWUiOiJDb3JkIiwic3RhdHVzIjoiYWN0aXZlIn0sIm9yZ2FuaXphdGlvbl9pZCI6IjQ0NTU2NiIsInVzZXJfZGV0YWlscyI6eyJlbWFpbCI6ImZsb29leUBleGFtcGxlLmNvbSIsIm5hbWUiOiJBZGFtIFZhcnRhbmlhbiIsInN0YXR1cyI6ImFjdGl2ZSIsImZpcnN0X25hbWUiOiJBZGFtIiwibGFzdF9uYW1lIjoiVmFydGFuaWFuIn0sInVzZXJfaWQiOiIxMTIyMzMifQ.fun1La5PVyjhSDbRB4fm9io80YMcK0Znghs0OMkeLjzxDFvwBY34elwO7CV2jApLV_-GL0DKHvyY6hQIUzgZXA" {
		t.Fatalf("Token generation failed, received %v", token)
	}
}

func TestClientAuthTokenEncoding(t *testing.T) {
	token, err := ClientAuthToken(kAppID, kSecret,
		ClientAuthTokenData{
			UserID:         kUserID,
			OrganizationID: kOrgID,
			UserDetails: &UserDetails{
				Email:  "flooey@example.com",
				Name:   "Adam Vartanian",
				Status: Active,
			},
			OrganizationDetails: &OrganizationDetails{
				Name:   "Cord",
				Status: Active,
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	payload := valuesFromToken(token)
	if payload["app_id"] != kAppID {
		t.Errorf("Wrong app ID, received %s", payload["app_id"])
	}
	if payload["user_id"] != kUserID {
		t.Errorf("Wrong user ID, received %s", payload["user_id"])
	}
	if payload["organization_id"] != kOrgID {
		t.Errorf("Wrong org ID, received %s", payload["organization_id"])
	}
	userDetails := payload["user_details"].(map[string]interface{})
	if userDetails["email"] != "flooey@example.com" {
		t.Errorf("Wrong email, received %s", userDetails["email"])
	}
	if userDetails["name"] != "Adam Vartanian" {
		t.Errorf("Wrong name, received %s", userDetails["name"])
	}
	if userDetails["status"] != "active" {
		t.Errorf("Wrong status, received %s", userDetails["status"])
	}
	if len(userDetails) > 3 {
		t.Errorf("Wrong number of user fields, received %d", len(userDetails))
	}
	orgDetails := payload["organization_details"].(map[string]interface{})
	if orgDetails["name"] != "Cord" {
		t.Errorf("Wrong name, received %s", orgDetails["name"])
	}
	if orgDetails["status"] != "active" {
		t.Errorf("Wrong status, received %s", orgDetails["status"])
	}
	if len(orgDetails) > 2 {
		t.Errorf("Wrong number of org fields, received %d", len(orgDetails))
	}
}

func TestClientAuthTokenMissingFields(t *testing.T) {
	_, err := ClientAuthToken(kAppID, kSecret, ClientAuthTokenData{})
	if err == nil {
		t.Error("Accepted empty ClientAuthTokenData")
	}
	_, err = ClientAuthToken(kAppID, kSecret, ClientAuthTokenData{UserID: kUserID})
	if err == nil {
		t.Error("Accepted missing organization ID")
	}
	_, err = ClientAuthToken(kAppID, kSecret, ClientAuthTokenData{OrganizationID: kOrgID})
	if err == nil {
		t.Error("Accepted missing user ID")
	}
	_, err = ClientAuthToken(kAppID, kSecret, ClientAuthTokenData{UserID: kUserID, OrganizationID: kOrgID, UserDetails: &UserDetails{}})
	if err == nil {
		t.Error("Accepted empty PlatformUserDetails")
	}
	_, err = ClientAuthToken(kAppID, kSecret, ClientAuthTokenData{UserID: kUserID, OrganizationID: kOrgID, OrganizationDetails: &OrganizationDetails{}})
	if err == nil {
		t.Error("Accepted empty PlaformOrganizationDetails")
	}
}
