/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package handlers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/responses"
	"github.com/vouch/vouch-proxy/pkg/structs"
)

var (
	errSessionNotFound = errors.New("/auth could not retrieve session")
	errInvalidState    = errors.New("/auth the state nonce returned by the IdP does not match the value stored in the session")
	errURLNotFound     = errors.New("/auth could not retrieve URL from session")
)

// CallbackHandler /auth
// - validate info from oauth provider (Google, GitHub, OIDC, etc)
// - issue jwt in the form of a cookie
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("/auth")
	// Handle the exchange code to initiate a transport.

	session, err := sessstore.Get(r, cfg.Cfg.Session.Name)
	if err != nil {
		responses.Error400(w, r, fmt.Errorf("/auth %w: could not find session store %s", err, cfg.Cfg.Session.Name))
		return
	}

	// is the nonce "state" valid?
	queryState := r.URL.Query().Get("state")
	if session.Values["state"] != queryState {
		responses.Error400(w, r, fmt.Errorf("/auth Invalid session state: stored %s, returned %s", session.Values["state"], queryState))
		return
	}

	// did the IdP return an error when they redirected back to /auth
	errorIDP := r.URL.Query().Get("error")
	if errorIDP != "" {
		errorDescription := r.URL.Query().Get("error_description")
		responses.Error401(w, r, fmt.Errorf("/auth Error from IdP: %s - %s", errorIDP, errorDescription))
		return
	}

	user := structs.User{}
	customClaims := structs.CustomClaims{}
	ptokens := structs.PTokens{}

	if err := getUserInfo(r, &user, &customClaims, &ptokens); err != nil {
		responses.Error400(w, r, fmt.Errorf("/auth Error while retreiving user info after successful login at the OAuth provider: %w", err))
		return
	}
	log.Debugf("/auth Claims from userinfo: %+v", customClaims)
	//getProviderJWT(r, &user)
	// log.Debug("/auth CallbackHandler")
	// log.Debugf("/auth %+v", user)

	// verify / authz the user
	if ok, err := verifyRequest(user, r); !ok {
		responses.Error403(w, r, fmt.Errorf("/auth User is not authorized: %w . Please try again or seek support from your administrator", err))
		return
	}

	// SUCCESS!! they are authorized

	// issue the jwt
	tokenstring := jwtmanager.CreateUserTokenString(user, customClaims, ptokens)
	cookie.SetCookie(w, r, tokenstring)

	// get the originally requested URL so we can send them on their way
	requestedURL := session.Values["requestedURL"].(string)
	if requestedURL != "" {
		// clear out the session value
		session.Values["requestedURL"] = ""
		session.Values[requestedURL] = 0
		session.Options.MaxAge = -1
		if err = session.Save(r, w); err != nil {
			log.Error(err)
		}

		responses.Redirect302(w, r, requestedURL)
		return
	}
	// otherwise serve an error (why isn't there a )
	responses.RenderIndex(w, "/auth "+tokenstring)
}

// verifyRequest validates that the domains match for the user
func verifyRequest(u interface{}, r *http.Request) (bool, error) {

	user := u.(structs.User)

	switch {

	// AllowAllUsers
	case cfg.Cfg.AllowAllUsers:
		log.Debugf("verifyRequest: Success! skipping verification, cfg.Cfg.AllowAllUsers is %t", cfg.Cfg.AllowAllUsers)
		return true, nil

	// AllowRules
	case len(cfg.Cfg.AllowRules) != 0:
		for _, ruleset := range cfg.Cfg.AllowRules {
			allow := true
		ruleset:
			for _, rule := range ruleset.Rules {
			rule:
				switch rule.Type {
				case "username":
					for _, username := range rule.Values {
						if username == user.Username {
							break rule
						}
					}
					allow = false
					break ruleset
				case "host":
					for _, host := range rule.Values {
						if host == r.Host {
							break rule
						}
					}
					allow = false
					break ruleset
				case "username:rx":
					for _, username := range rule.ValuesRx {
						if username.Match([]byte(user.Username)) {
							break rule
						}
					}
					allow = false
					break ruleset
				case "host:rx":
					for _, host := range rule.ValuesRx {
						if host.Match([]byte(r.Host)) {
							break rule
						}
					}
					allow = false
					break ruleset
				}
			}
			// Only if all rules have matched
			if allow {
				log.Debugf("verifyRequest: Success! request matches rule in AllowRules for user.Username and rule: %s, %s", user.Username, ruleset.Name)
				return true, nil
			}
		}

		return false, fmt.Errorf("verifyRequest: no rule matches for user.Username in AllowRules: %s", user.Username)

	// WhiteList
	case len(cfg.Cfg.WhiteList) != 0:
		for _, wl := range cfg.Cfg.WhiteList {
			if user.Username == wl {
				log.Debugf("verifyRequest: Success! found user.Username in WhiteList: %s", user.Username)
				return true, nil
			}
		}
		return false, fmt.Errorf("verifyRequest: user.Username not found in WhiteList: %s", user.Username)

	// TeamWhiteList
	case len(cfg.Cfg.TeamWhiteList) != 0:
		for _, team := range user.TeamMemberships {
			for _, wl := range cfg.Cfg.TeamWhiteList {
				if team == wl {
					log.Debugf("verifyRequest: Success! found user.TeamWhiteList in TeamWhiteList: %s for user %s", wl, user.Username)
					return true, nil
				}
			}
		}
		return false, fmt.Errorf("verifyRequest: user.TeamMemberships %s not found in TeamWhiteList: %s for user %s", user.TeamMemberships, cfg.Cfg.TeamWhiteList, user.Username)

	// Domains
	case len(cfg.Cfg.Domains) != 0:
		if domains.IsUnderManagement(user.Email) {
			log.Debugf("verifyRequest: Success! Email %s found within a "+cfg.Branding.FullName+" managed domain", user.Email)
			return true, nil
		}
		return false, fmt.Errorf("verifyRequest: Email %s is not within a "+cfg.Branding.FullName+" managed domain", user.Email)

	// nothing configured, allow everyone through
	default:
		log.Warn("verifyRequest: no domains, whitelist, teamWhitelist or AllowAllUsers configured, any successful auth to the IdP authorizes access")
		return true, nil
	}
}

func getUserInfo(r *http.Request, user *structs.User, customClaims *structs.CustomClaims, ptokens *structs.PTokens) error {
	return provider.GetUserInfo(r, user, customClaims, ptokens)
}
