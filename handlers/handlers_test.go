/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/responses"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

var (
	token = &oauth2.Token{AccessToken: "123"}
)

// setUp load config file and then call Configure() for dependent packages
func setUp(configFile string) {
	os.Setenv("VOUCH_CONFIG", filepath.Join(os.Getenv("VOUCH_ROOT"), configFile))
	cfg.InitForTestPurposes()

	Configure()
	domains.Configure()
	jwtmanager.Configure()
	cookie.Configure()
	responses.Configure()

}

func TestVerifyUserPositiveUserInWhiteList(t *testing.T) {
	setUp("/config/testing/handler_whitelist.yml")
	user := &structs.User{Username: "test@example.com", Email: "test@example.com", Name: "Test Name"}
	ok, err := verifyRequest(*user, &http.Request{})
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveAllowAllUsers(t *testing.T) {
	setUp("/config/testing/handler_allowallusers.yml")

	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}

	ok, err := verifyRequest(*user, &http.Request{})
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveByEmail(t *testing.T) {
	setUp("/config/testing/handler_email.yml")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	ok, err := verifyRequest(*user, &http.Request{})
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserPositiveByTeam(t *testing.T) {
	setUp("/config/testing/handler_teams.yml")

	// cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "org1/team2", "org1/team1")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	user.TeamMemberships = append(user.TeamMemberships, "org1/team3")
	user.TeamMemberships = append(user.TeamMemberships, "org1/team1")
	ok, err := verifyRequest(*user, &http.Request{})
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserNegativeByTeam(t *testing.T) {
	setUp("/config/testing/handler_teams.yml")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	// cfg.Cfg.TeamWhiteList = append(cfg.Cfg.TeamWhiteList, "org1/team1")

	ok, err := verifyRequest(*user, &http.Request{})
	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestVerifyUserPositiveNoDomainsConfigured(t *testing.T) {
	setUp("/config/testing/handler_nodomains.yml")

	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	cfg.Cfg.Domains = make([]string, 0)
	ok, err := verifyRequest(*user, &http.Request{})

	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyUserNegative(t *testing.T) {
	setUp("/config/testing/test_config.yml")
	user := &structs.User{Username: "testuser", Email: "test@example.com", Name: "Test Name"}
	ok, err := verifyRequest(*user, &http.Request{})

	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestVerifyAdminPositiveInAllowRules(t *testing.T) {
	setUp("/config/testing/handler_allowrules.yml")
	user := &structs.User{Username: "admin@example.com", Email: "admin@example.com", Name: "Admin Name"}
	ok, err := verifyRequest(*user, &http.Request{})
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyAnotherAdminPositiveInAllowRules(t *testing.T) {
	setUp("/config/testing/handler_allowrules.yml")
	user := &structs.User{Username: "admin@another.org", Email: "admin@another.org", Name: "Another admin name"}
	ok, err := verifyRequest(*user, &http.Request{})
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestVerifyAnotherAdminNegativeInAllowRules(t *testing.T) {
	setUp("/config/testing/handler_allowrules.yml")
	user := &structs.User{Username: "admin@notfound.org", Email: "admin@notfound.org", Name: "Not found admin name"}
	ok, err := verifyRequest(*user, &http.Request{})
	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestMediaUserPositiveInAllowRules(t *testing.T) {
	setUp("/config/testing/handler_allowrules.yml")
	user := &structs.User{Username: "foo@example.com", Email: "foo@example.com", Name: "Foo"}
	ok, err := verifyRequest(*user, &http.Request{Host: "videos-01.example.com"})
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestAnotherMediaUserPositiveInAllowRules(t *testing.T) {
	setUp("/config/testing/handler_allowrules.yml")
	user := &structs.User{Username: "bar@example.com", Email: "bar@example.com", Name: "Bar"}
	ok, err := verifyRequest(*user, &http.Request{Host: "photos-99.example.com"})
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestMediaUserUsernameNegativeInAllowRules(t *testing.T) {
	setUp("/config/testing/handler_allowrules.yml")
	user := &structs.User{Username: "bar@another.org", Email: "bar@another.org", Name: "Bar"}
	ok, err := verifyRequest(*user, &http.Request{Host: "photos-99.example.com"})
	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestMediaUserHostNegativeInAllowRules(t *testing.T) {
	setUp("/config/testing/handler_allowrules.yml")
	user := &structs.User{Username: "foo@example.com", Email: "foo@example.com", Name: "Foo"}
	ok, err := verifyRequest(*user, &http.Request{Host: "media.example.com"})
	assert.False(t, ok)
	assert.NotNil(t, err)
}

// copied from jwtmanager_test.go
// it should live there but circular imports are resolved if it lives here
var (
	u1 = structs.User{
		Username: "test@testing.com",
		Name:     "Test Name",
	}
	t1 = structs.PTokens{
		PAccessToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRvaXU4In0.eyJzdWIiOiJuZnlmZSIsImF1ZCI6ImltX29pY19jbGllbnQiLCJqdGkiOiJUOU4xUklkRkVzUE45enU3ZWw2eng2IiwiaXNzIjoiaHR0cHM6XC9cL3Nzby5tZXljbG91ZC5uZXQ6OTAzMSIsImlhdCI6MTM5MzczNzA3MSwiZXhwIjoxMzkzNzM3MzcxLCJub25jZSI6ImNiYTU2NjY2LTRiMTItNDU2YS04NDA3LTNkMzAyM2ZhMTAwMiIsImF0X2hhc2giOiJrdHFvZVBhc2praVY5b2Z0X3o5NnJBIn0.g1Jc9DohWFfFG3ppWfvW16ib6YBaONC5VMs8J61i5j5QLieY-mBEeVi1D3vr5IFWCfivY4hZcHtoJHgZk1qCumkAMDymsLGX-IGA7yFU8LOjUdR4IlCPlZxZ_vhqr_0gQ9pCFKDkiOv1LVv5x3YgAdhHhpZhxK6rWxojg2RddzvZ9Xi5u2V1UZ0jukwyG2d4PRzDn7WoRNDGwYOEt4qY7lv_NO2TY2eAklP-xYBWu0b9FBElapnstqbZgAXdndNs-Wqp4gyQG5D0owLzxPErR9MnpQfgNcai-PlWI_UrvoopKNbX0ai2zfkuQ-qh6Xn8zgkiaYDHzq4gzwRfwazaqA",
		PIdToken:     "eyJhbGciOiJSUzI1NiIsImtpZCI6IjRvaXU4In0.eyJzdWIiOiJuZnlmZSIsImF1ZCI6ImltX29pY19jbGllbnQiLCJqdGkiOiJUOU4xUklkRkVzUE45enU3ZWw2eng2IiwiaXNzIjoiaHR0cHM6XC9cL3Nzby5tZXljbG91ZC5uZXQ6OTAzMSIsImlhdCI6MTM5MzczNzA3MSwiZXhwIjoxMzkzNzM3MzcxLCJub25jZSI6ImNiYTU2NjY2LTRiMTItNDU2YS04NDA3LTNkMzAyM2ZhMTAwMiIsImF0X2hhc2giOiJrdHFvZVBhc2praVY5b2Z0X3o5NnJBIn0.g1Jc9DohWFfFG3ppWfvW16ib6YBaONC5VMs8J61i5j5QLieY-mBEeVi1D3vr5IFWCfivY4hZcHtoJHgZk1qCumkAMDymsLGX-IGA7yFU8LOjUdR4IlCPlZxZ_vhqr_0gQ9pCFKDkiOv1LVv5x3YgAdhHhpZhxK6rWxojg2RddzvZ9Xi5u2V1UZ0jukwyG2d4PRzDn7WoRNDGwYOEt4qY7lv_NO2TY2eAklP-xYBWu0b9FBElapnstqbZgAXdndNs-Wqp4gyQG5D0owLzxPErR9MnpQfgNcai-PlWI_UrvoopKNbX0ai2zfkuQ-qh6Xn8zgkiaYDHzq4gzwRfwazaqA",
	}

	lc jwtmanager.VouchClaims

	claimjson = `{
		"sub": "f:a95afe53-60ba-4ac6-af15-fab870e72f3d:mrtester",
		"groups": ["Website Users", "Test Group"],
		"given_name": "Mister",
		"family_name": "Tester",
		"email": "mrtester@test.int"
	}`
	customClaims = structs.CustomClaims{}
)

// copied from jwtmanager_test.go
func init() {
	// log.SetLevel(log.DebugLevel)

	lc = jwtmanager.VouchClaims{
		u1.Username,
		jwtmanager.Sites,
		customClaims.Claims,
		t1.PAccessToken,
		t1.PIdToken,
		jwtmanager.StandardClaims,
	}
	json.Unmarshal([]byte(claimjson), &customClaims.Claims)
}

func TestParsedIdPTokens(t *testing.T) {
	tests := []struct {
		name          string
		configFile    string
		wantIDPTokens bool
	}{
		{"no IdP tokens", "/config/testing/handler_claims.yml", false},
		{"wants IdP tokens", "/config/testing/jwtmanager_has_idp_token_claims.yml", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setUp(tt.configFile)
			uts := jwtmanager.CreateUserTokenString(u1, customClaims, t1)
			utsParsed, _ := jwtmanager.ParseTokenString(uts)
			utsPtokens, _ := jwtmanager.PTokenClaims(utsParsed)

			if tt.wantIDPTokens {
				if t1.PIdToken != utsPtokens.PIdToken || t1.PAccessToken != utsPtokens.PAccessToken {
					t.Errorf("got PIdToken = %s, PAccessToken = %s, \nwant %s , %s", utsPtokens.PIdToken, utsPtokens.PAccessToken, t1.PIdToken, t1.PAccessToken)
				}
			} else {
				if utsPtokens.PIdToken != "" || utsPtokens.PAccessToken != "" {
					t.Errorf("PIdToken and PAccessToken = should be '' got '%s', '%s'", utsPtokens.PIdToken, utsPtokens.PAccessToken)
				}
			}
		})
	}

}
