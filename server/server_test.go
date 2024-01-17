package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var (
	kAppID          = "1234567890"
	kSecret         = []byte("0987654321")
	kUserID         = "112233"
	kGroupID        = "445566"
	kCustomerID     = "345456567"
	kCustomerSecret = []byte("123234345")
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

func TestApplicationManagementAuthTokenBasics(t *testing.T) {
	token, err := ApplicationManagementAuthToken(kCustomerID, kCustomerSecret)

	if err != nil {
		t.Fatal(err)
	}
	if token != "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJjdXN0b21lcl9pZCI6IjM0NTQ1NjU2NyIsImV4cCI6MTY1NTM4MzE3MywiaWF0IjoxNjU1MzgzMTEzfQ.nxfnM4F4jp9lckTec8a7r5garU57KleN_qnV7eaUePaxScKhIpFTWgpFpa_Xj7hooJ0bTZN5Rk4VB1TgWg-f2Q" {
		t.Fatalf("Token generation failed, received %v", token)
	}
}

func TestClientAuthTokenBasics(t *testing.T) {
	token, err := ClientAuthToken(kAppID, kSecret,
		ClientAuthTokenData{
			UserID:  kUserID,
			GroupID: kGroupID,
			UserDetails: &UserDetails{
				Email:  "flooey@example.com",
				Name:   "Adam Vartanian",
				Status: Active,
			},
			GroupDetails: &GroupDetails{
				Name:   "Cord",
				Status: Active,
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	if token != "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhcHBfaWQiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjU1MzgzMTczLCJncm91cF9kZXRhaWxzIjp7Im5hbWUiOiJDb3JkIiwic3RhdHVzIjoiYWN0aXZlIn0sImdyb3VwX2lkIjoiNDQ1NTY2IiwiaWF0IjoxNjU1MzgzMTEzLCJ1c2VyX2RldGFpbHMiOnsiZW1haWwiOiJmbG9vZXlAZXhhbXBsZS5jb20iLCJuYW1lIjoiQWRhbSBWYXJ0YW5pYW4iLCJzdGF0dXMiOiJhY3RpdmUifSwidXNlcl9pZCI6IjExMjIzMyJ9.SFC9fhZlkOQIfDswKk9y8cvXKzdy--PWZAXWYVt8XkUrkoeuxhXeZhnxsYk6iXzZXSoPti5_oHbTr45AvznXuQ" {
		t.Fatalf("Token generation failed, received %v", token)
	}
}

func TestClientAuthTokenNoGroup(t *testing.T) {
	token, err := ClientAuthToken(kAppID, kSecret,
		ClientAuthTokenData{
			UserID: kUserID,
			UserDetails: &UserDetails{
				Email: "flooey@example.com",
				Name:  "Adam Vartanian",
				Metadata: map[string]interface{}{
					"employee":                true,
					"employee_id":             12345,
					"employee_favorite_movie": "The Princess Bride",
				},
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	if token != "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhcHBfaWQiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjU1MzgzMTczLCJpYXQiOjE2NTUzODMxMTMsInVzZXJfZGV0YWlscyI6eyJlbWFpbCI6ImZsb29leUBleGFtcGxlLmNvbSIsIm5hbWUiOiJBZGFtIFZhcnRhbmlhbiIsIm1ldGFkYXRhIjp7ImVtcGxveWVlIjp0cnVlLCJlbXBsb3llZV9mYXZvcml0ZV9tb3ZpZSI6IlRoZSBQcmluY2VzcyBCcmlkZSIsImVtcGxveWVlX2lkIjoxMjM0NX19LCJ1c2VyX2lkIjoiMTEyMjMzIn0.oN7LfxdaCBqlc_t2Btb9qi3jiaz0SlZxkzplnNlJaR3mK_B99pK20YDiO8rEPcPkYw6qozqDljUdAN5FMz8wgA" {
		t.Fatalf("Token generation failed, received %v", token)
	}
}

func TestClientAuthTokenDeprecatedFeatures(t *testing.T) {
	token, err := ClientAuthToken(kAppID, kSecret,
		ClientAuthTokenData{
			UserID: kUserID,
			// This is called GroupID now
			OrganizationID: kGroupID,
			UserDetails: &UserDetails{
				Email: "flooey@example.com",
				Name:  "Adam Vartanian",
				// FirstName and LastName are deprecated and ignored
				FirstName: "Adam",
				LastName:  "Vartanian",
				Status:    Active,
			},
			// This is called GroupDetails now
			OrganizationDetails: &OrganizationDetails{
				Name:   "Cord",
				Status: Active,
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	if token != "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhcHBfaWQiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjU1MzgzMTczLCJncm91cF9kZXRhaWxzIjp7Im5hbWUiOiJDb3JkIiwic3RhdHVzIjoiYWN0aXZlIn0sImdyb3VwX2lkIjoiNDQ1NTY2IiwiaWF0IjoxNjU1MzgzMTEzLCJ1c2VyX2RldGFpbHMiOnsiZW1haWwiOiJmbG9vZXlAZXhhbXBsZS5jb20iLCJuYW1lIjoiQWRhbSBWYXJ0YW5pYW4iLCJzdGF0dXMiOiJhY3RpdmUifSwidXNlcl9pZCI6IjExMjIzMyJ9.SFC9fhZlkOQIfDswKk9y8cvXKzdy--PWZAXWYVt8XkUrkoeuxhXeZhnxsYk6iXzZXSoPti5_oHbTr45AvznXuQ" {
		t.Fatalf("Token generation failed, received %v", token)
	}
}

func TestClientAuthTokenEncoding(t *testing.T) {
	token, err := ClientAuthToken(kAppID, kSecret,
		ClientAuthTokenData{
			UserID:  kUserID,
			GroupID: kGroupID,
			UserDetails: &UserDetails{
				Email:  "flooey@example.com",
				Name:   "Adam Vartanian",
				Status: Active,
				Metadata: map[string]interface{}{
					"employee":                true,
					"employee_id":             12345,
					"employee_favorite_movie": "The Princess Bride",
				},
			},
			GroupDetails: &GroupDetails{
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
	if payload["group_id"] != kGroupID {
		t.Errorf("Wrong group ID, received %s", payload["group_id"])
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
	userMetadata := userDetails["metadata"].(map[string]interface{})
	if userMetadata["employee"] != true {
		t.Errorf("Wrong metadata:employee, received %v", userMetadata["employee"])
	}
	if userMetadata["employee_id"] != 12345.0 {
		t.Errorf("Wrong metadata:employee_id, received %v", userMetadata["employee_id"])
	}
	if userMetadata["employee_favorite_movie"] != "The Princess Bride" {
		t.Errorf("Wrong metadata:employee_favorite_movie, received %v", userMetadata["employee_favorite_movie"])
	}
	if len(userMetadata) > 3 {
		t.Errorf("Wrong number of user metadata fields, received %d", len(userMetadata))
	}
	if len(userDetails) > 4 {
		t.Errorf("Wrong number of user fields, received %d", len(userDetails))
	}
	groupDetails := payload["group_details"].(map[string]interface{})
	if groupDetails["name"] != "Cord" {
		t.Errorf("Wrong name, received %s", groupDetails["name"])
	}
	if groupDetails["status"] != "active" {
		t.Errorf("Wrong status, received %s", groupDetails["status"])
	}
	if len(groupDetails) > 2 {
		t.Errorf("Wrong number of group fields, received %d", len(groupDetails))
	}
}

func TestClientAuthTokenMissingFields(t *testing.T) {
	_, err := ClientAuthToken(kAppID, kSecret, ClientAuthTokenData{})
	if err == nil {
		t.Error("Accepted empty ClientAuthTokenData")
	}
	_, err = ClientAuthToken(kAppID, kSecret, ClientAuthTokenData{GroupID: kGroupID})
	if err == nil {
		t.Error("Accepted missing user ID")
	}
	_, err = ClientAuthToken(kAppID, kSecret, ClientAuthTokenData{UserID: kUserID, GroupID: kGroupID, GroupDetails: &GroupDetails{}})
	if err == nil {
		t.Error("Accepted empty PlaformGroupDetails")
	}
}
