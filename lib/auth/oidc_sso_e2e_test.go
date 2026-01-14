/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authtest"
	"github.com/gravitational/teleport/lib/modules"
)

func init() {
	modules.SetInsecureTestMode(true)
}

// FakeOIDCProvider implements a minimal OIDC Identity Provider for testing.
type FakeOIDCProvider struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	keyID      string
}

// NewFakeOIDCProvider creates a new fake OIDC provider for testing.
func NewFakeOIDCProvider(t *testing.T) *FakeOIDCProvider {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	provider := &FakeOIDCProvider{
		privateKey: privateKey,
		keyID:      "test-key-1",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", provider.handleOpenIDConfig)
	mux.HandleFunc("/.well-known/jwks.json", provider.handleJWKS)
	mux.HandleFunc("/authorize", provider.handleAuthorize)
	mux.HandleFunc("/token", provider.handleToken)

	provider.server = httptest.NewServer(mux)
	return provider
}

// Close shuts down the fake OIDC provider.
func (p *FakeOIDCProvider) Close() {
	p.server.Close()
}

// IssuerURL returns the issuer URL of the fake OIDC provider.
func (p *FakeOIDCProvider) IssuerURL() string {
	return p.server.URL
}

func (p *FakeOIDCProvider) handleOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"issuer":                                p.IssuerURL(),
		"authorization_endpoint":               p.IssuerURL() + "/authorize",
		"token_endpoint":                       p.IssuerURL() + "/token",
		"jwks_uri":                             p.IssuerURL() + "/.well-known/jwks.json",
		"response_types_supported":             []string{"code", "id_token"},
		"subject_types_supported":              []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                     []string{"openid", "email", "profile"},
		"claims_supported":                     []string{"sub", "email", "email_verified", "name", "groups"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (p *FakeOIDCProvider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       &p.privateKey.PublicKey,
		KeyID:     p.keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func (p *FakeOIDCProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// In a real flow, this would show a login page. For testing, we just redirect back.
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")

	// Generate a fake authorization code.
	code := "fake-auth-code-" + state

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, code, state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (p *FakeOIDCProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	// Generate an ID token.
	idToken, err := p.IssueIDToken("test-user@example.com", "test-user", []string{"admin-group"})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"access_token":  "fake-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"id_token":      idToken,
		"refresh_token": "fake-refresh-token",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// IssueIDToken generates a signed ID token with the given claims.
func (p *FakeOIDCProvider) IssueIDToken(email, username string, groups []string) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.keyID),
	)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := map[string]interface{}{
		"iss":            p.IssuerURL(),
		"sub":            "user-id-12345",
		"aud":            "test-client-id",
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"email":          email,
		"email_verified": true,
		"name":           username,
		"groups":         groups,
	}

	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

// TestOIDCSSOE2E_ConnectorCreation tests creating an OIDC connector.
func TestOIDCSSOE2E_ConnectorCreation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testAuthServer, err := authtest.NewAuthServer(authtest.AuthServerConfig{
		Dir: t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testAuthServer.Close()) })

	testServer, err := testAuthServer.NewTestTLSServer()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testServer.Close()) })

	a := testServer.Auth()

	// Create a fake OIDC provider.
	fakeProvider := NewFakeOIDCProvider(t)
	t.Cleanup(fakeProvider.Close)

	// Create test role that will be mapped from claims.
	role, err := types.NewRole("oidc-admin", types.RoleSpecV6{})
	require.NoError(t, err)
	_, err = a.UpsertRole(ctx, role)
	require.NoError(t, err)

	// Create an OIDC connector pointing to our fake provider.
	connector, err := types.NewOIDCConnector("test-oidc", types.OIDCConnectorSpecV3{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		IssuerURL:    fakeProvider.IssuerURL(),
		RedirectURLs: []string{"https://proxy.example.com/v1/webapi/oidc/callback"},
		ClaimsToRoles: []types.ClaimMapping{
			{
				Claim: "groups",
				Value: "admin-group",
				Roles: []string{"oidc-admin"},
			},
		},
	})
	require.NoError(t, err)

	// Upsert the connector.
	upsertedConnector, err := a.UpsertOIDCConnector(ctx, connector)
	require.NoError(t, err)
	assert.Equal(t, "test-oidc", upsertedConnector.GetName())
	assert.Equal(t, fakeProvider.IssuerURL(), upsertedConnector.GetIssuerURL())

	// Retrieve the connector.
	retrievedConnector, err := a.GetOIDCConnector(ctx, "test-oidc", true)
	require.NoError(t, err)
	assert.Equal(t, "test-client-id", retrievedConnector.GetClientID())
	assert.Equal(t, "test-client-secret", retrievedConnector.GetClientSecret())
	assert.Equal(t, 1, len(retrievedConnector.GetClaimsToRoles()))
}

// TestOIDCSSOE2E_AuthRequestFlow tests the OIDC auth request creation flow.
func TestOIDCSSOE2E_AuthRequestFlow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testAuthServer, err := authtest.NewAuthServer(authtest.AuthServerConfig{
		Dir: t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testAuthServer.Close()) })

	testServer, err := testAuthServer.NewTestTLSServer()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testServer.Close()) })

	a := testServer.Auth()

	// Create a fake OIDC provider.
	fakeProvider := NewFakeOIDCProvider(t)
	t.Cleanup(fakeProvider.Close)

	// Create test role.
	role, err := types.NewRole("test-role", types.RoleSpecV6{})
	require.NoError(t, err)
	_, err = a.UpsertRole(ctx, role)
	require.NoError(t, err)

	// Create an OIDC connector.
	connector, err := types.NewOIDCConnector("e2e-test-oidc", types.OIDCConnectorSpecV3{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		IssuerURL:    fakeProvider.IssuerURL(),
		RedirectURLs: []string{"https://proxy.example.com/v1/webapi/oidc/callback"},
		ClaimsToRoles: []types.ClaimMapping{
			{
				Claim: "groups",
				Value: ".*",
				Roles: []string{"test-role"},
			},
		},
	})
	require.NoError(t, err)
	_, err = a.UpsertOIDCConnector(ctx, connector)
	require.NoError(t, err)

	// Test creating an auth request with SSOTestFlow.
	t.Run("SSOTestFlow creates auth request", func(t *testing.T) {
		connSpec := &types.OIDCConnectorSpecV3{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			IssuerURL:    fakeProvider.IssuerURL(),
			RedirectURLs: []string{"https://test.example.com/callback"},
			ClaimsToRoles: []types.ClaimMapping{
				{
					Claim: "groups",
					Value: ".*",
					Roles: []string{"test-role"},
				},
			},
		}

		req := types.OIDCAuthRequest{
			ConnectorID:      "test-connector",
			SSOTestFlow:      true,
			ConnectorSpec:    connSpec,
			CreateWebSession: true,
		}

		// Create auth request with fake OIDC provider.
		authReq, err := a.CreateOIDCAuthRequest(ctx, req)
		require.NoError(t, err)
		assert.NotEmpty(t, authReq.StateToken)
		assert.NotEmpty(t, authReq.RedirectURL)
		assert.Contains(t, authReq.RedirectURL, fakeProvider.IssuerURL())
	})
}

// TestOIDCSSOE2E_ClaimsMappingConfiguration tests various claims-to-roles mapping configurations.
func TestOIDCSSOE2E_ClaimsMappingConfiguration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testAuthServer, err := authtest.NewAuthServer(authtest.AuthServerConfig{
		Dir: t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testAuthServer.Close()) })

	testServer, err := testAuthServer.NewTestTLSServer()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testServer.Close()) })

	a := testServer.Auth()

	// Create a fake OIDC provider.
	fakeProvider := NewFakeOIDCProvider(t)
	t.Cleanup(fakeProvider.Close)

	// Create test roles.
	for _, roleName := range []string{"admin", "developer", "viewer"} {
		role, err := types.NewRole(roleName, types.RoleSpecV6{})
		require.NoError(t, err)
		_, err = a.UpsertRole(ctx, role)
		require.NoError(t, err)
	}

	testCases := []struct {
		name          string
		claimsMapping []types.ClaimMapping
		expectRoles   int
	}{
		{
			name: "single claim mapping",
			claimsMapping: []types.ClaimMapping{
				{Claim: "groups", Value: "admins", Roles: []string{"admin"}},
			},
			expectRoles: 1,
		},
		{
			name: "multiple claim mappings",
			claimsMapping: []types.ClaimMapping{
				{Claim: "groups", Value: "admins", Roles: []string{"admin"}},
				{Claim: "groups", Value: "devs", Roles: []string{"developer"}},
				{Claim: "department", Value: "engineering", Roles: []string{"viewer"}},
			},
			expectRoles: 3,
		},
		{
			name: "regex pattern mapping",
			claimsMapping: []types.ClaimMapping{
				{Claim: "groups", Value: "admin.*", Roles: []string{"admin"}},
			},
			expectRoles: 1,
		},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			connectorName := fmt.Sprintf("claims-test-%d", i)
			connector, err := types.NewOIDCConnector(connectorName, types.OIDCConnectorSpecV3{
				ClientID:      "client-id",
				ClientSecret:  "client-secret",
				IssuerURL:     fakeProvider.IssuerURL(),
				RedirectURLs:  []string{"https://proxy.example.com/callback"},
				ClaimsToRoles: tc.claimsMapping,
			})
			require.NoError(t, err)

			_, err = a.UpsertOIDCConnector(ctx, connector)
			require.NoError(t, err)

			retrieved, err := a.GetOIDCConnector(ctx, connectorName, false)
			require.NoError(t, err)
			assert.Equal(t, tc.expectRoles, len(retrieved.GetClaimsToRoles()))
		})
	}
}

// TestOIDCSSOE2E_PKCEConfiguration tests PKCE mode configuration.
func TestOIDCSSOE2E_PKCEConfiguration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testAuthServer, err := authtest.NewAuthServer(authtest.AuthServerConfig{
		Dir: t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testAuthServer.Close()) })

	testServer, err := testAuthServer.NewTestTLSServer()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testServer.Close()) })

	a := testServer.Auth()

	fakeProvider := NewFakeOIDCProvider(t)
	t.Cleanup(fakeProvider.Close)

	// Create test role.
	role, err := types.NewRole("pkce-test-role", types.RoleSpecV6{})
	require.NoError(t, err)
	_, err = a.UpsertRole(ctx, role)
	require.NoError(t, err)

	// Test connector with PKCE enabled.
	connector, err := types.NewOIDCConnector("pkce-enabled", types.OIDCConnectorSpecV3{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		IssuerURL:    fakeProvider.IssuerURL(),
		RedirectURLs: []string{"https://proxy.example.com/callback"},
		PKCEMode:     "enabled",
		ClaimsToRoles: []types.ClaimMapping{
			{Claim: "groups", Value: ".*", Roles: []string{"pkce-test-role"}},
		},
	})
	require.NoError(t, err)

	_, err = a.UpsertOIDCConnector(ctx, connector)
	require.NoError(t, err)

	retrieved, err := a.GetOIDCConnector(ctx, "pkce-enabled", false)
	require.NoError(t, err)
	assert.True(t, retrieved.IsPKCEEnabled())
}

// TestOIDCSSOE2E_MFAConfiguration tests MFA settings on OIDC connectors.
func TestOIDCSSOE2E_MFAConfiguration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testAuthServer, err := authtest.NewAuthServer(authtest.AuthServerConfig{
		Dir: t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testAuthServer.Close()) })

	testServer, err := testAuthServer.NewTestTLSServer()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testServer.Close()) })

	a := testServer.Auth()

	fakeProvider := NewFakeOIDCProvider(t)
	t.Cleanup(fakeProvider.Close)

	// Create test role.
	role, err := types.NewRole("mfa-test-role", types.RoleSpecV6{})
	require.NoError(t, err)
	_, err = a.UpsertRole(ctx, role)
	require.NoError(t, err)

	// Test connector with MFA enabled.
	connector, err := types.NewOIDCConnector("mfa-enabled", types.OIDCConnectorSpecV3{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		IssuerURL:    fakeProvider.IssuerURL(),
		RedirectURLs: []string{"https://proxy.example.com/callback"},
		ClaimsToRoles: []types.ClaimMapping{
			{Claim: "groups", Value: ".*", Roles: []string{"mfa-test-role"}},
		},
		MFASettings: &types.OIDCConnectorMFASettings{
			Enabled:      true,
			ClientId:     "mfa-client-id",
			ClientSecret: "mfa-client-secret",
		},
	})
	require.NoError(t, err)

	_, err = a.UpsertOIDCConnector(ctx, connector)
	require.NoError(t, err)

	retrieved, err := a.GetOIDCConnector(ctx, "mfa-enabled", true)
	require.NoError(t, err)
	assert.True(t, retrieved.IsMFAEnabled())

	mfaSettings := retrieved.GetMFASettings()
	require.NotNil(t, mfaSettings)
	assert.Equal(t, "mfa-client-id", mfaSettings.ClientId)
}

// TestOIDCSSOE2E_ConnectorLifecycle tests the full lifecycle of an OIDC connector.
func TestOIDCSSOE2E_ConnectorLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testAuthServer, err := authtest.NewAuthServer(authtest.AuthServerConfig{
		Dir: t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testAuthServer.Close()) })

	testServer, err := testAuthServer.NewTestTLSServer()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testServer.Close()) })

	a := testServer.Auth()

	fakeProvider := NewFakeOIDCProvider(t)
	t.Cleanup(fakeProvider.Close)

	// Create test role.
	role, err := types.NewRole("lifecycle-role", types.RoleSpecV6{})
	require.NoError(t, err)
	_, err = a.UpsertRole(ctx, role)
	require.NoError(t, err)

	connectorName := "lifecycle-test"

	// 1. Create connector.
	connector, err := types.NewOIDCConnector(connectorName, types.OIDCConnectorSpecV3{
		ClientID:     "initial-client-id",
		ClientSecret: "initial-client-secret",
		IssuerURL:    fakeProvider.IssuerURL(),
		RedirectURLs: []string{"https://proxy.example.com/callback"},
		ClaimsToRoles: []types.ClaimMapping{
			{Claim: "groups", Value: "users", Roles: []string{"lifecycle-role"}},
		},
	})
	require.NoError(t, err)

	created, err := a.UpsertOIDCConnector(ctx, connector)
	require.NoError(t, err)
	assert.Equal(t, "initial-client-id", created.GetClientID())

	// 2. List connectors.
	connectors, err := a.GetOIDCConnectors(ctx, false)
	require.NoError(t, err)
	found := false
	for _, c := range connectors {
		if c.GetName() == connectorName {
			found = true
			break
		}
	}
	assert.True(t, found, "connector should be in list")

	// 3. Update connector.
	connector.SetClientID("updated-client-id")
	updated, err := a.UpsertOIDCConnector(ctx, connector)
	require.NoError(t, err)
	assert.Equal(t, "updated-client-id", updated.GetClientID())

	// 4. Delete connector.
	err = a.DeleteOIDCConnector(ctx, connectorName)
	require.NoError(t, err)

	// 5. Verify deletion.
	_, err = a.GetOIDCConnector(ctx, connectorName, false)
	require.Error(t, err)
	assert.True(t, err != nil) // Connector should not exist.
}

// TestOIDCSSOE2E_MultipleRedirectURLs tests connectors with multiple redirect URLs.
func TestOIDCSSOE2E_MultipleRedirectURLs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testAuthServer, err := authtest.NewAuthServer(authtest.AuthServerConfig{
		Dir: t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testAuthServer.Close()) })

	testServer, err := testAuthServer.NewTestTLSServer()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testServer.Close()) })

	a := testServer.Auth()

	fakeProvider := NewFakeOIDCProvider(t)
	t.Cleanup(fakeProvider.Close)

	// Create test role.
	role, err := types.NewRole("redirect-role", types.RoleSpecV6{})
	require.NoError(t, err)
	_, err = a.UpsertRole(ctx, role)
	require.NoError(t, err)

	// Create connector with multiple redirect URLs.
	redirectURLs := []string{
		"https://proxy1.example.com/callback",
		"https://proxy2.example.com/callback",
		"https://proxy3.example.com/callback",
	}

	connector, err := types.NewOIDCConnector("multi-redirect", types.OIDCConnectorSpecV3{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		IssuerURL:    fakeProvider.IssuerURL(),
		RedirectURLs: redirectURLs,
		ClaimsToRoles: []types.ClaimMapping{
			{Claim: "groups", Value: ".*", Roles: []string{"redirect-role"}},
		},
	})
	require.NoError(t, err)

	_, err = a.UpsertOIDCConnector(ctx, connector)
	require.NoError(t, err)

	retrieved, err := a.GetOIDCConnector(ctx, "multi-redirect", false)
	require.NoError(t, err)
	assert.Equal(t, 3, len(retrieved.GetRedirectURLs()))
}

// TestOIDCSSOE2E_CallbackValidation tests the callback validation flow.
func TestOIDCSSOE2E_CallbackValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testAuthServer, err := authtest.NewAuthServer(authtest.AuthServerConfig{
		Dir: t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testAuthServer.Close()) })

	testServer, err := testAuthServer.NewTestTLSServer()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testServer.Close()) })

	a := testServer.Auth()

	// Test callback with missing state.
	t.Run("missing state returns error", func(t *testing.T) {
		values := url.Values{}
		values.Set("code", "some-code")
		// state is missing

		_, err := a.ValidateOIDCAuthCallback(ctx, values)
		require.Error(t, err)
	})

	// Test callback with error from IdP.
	t.Run("IdP error is propagated", func(t *testing.T) {
		values := url.Values{}
		values.Set("error", "access_denied")
		values.Set("error_description", "User denied access")
		values.Set("state", "some-state")

		_, err := a.ValidateOIDCAuthCallback(ctx, values)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_denied")
	})

	// Test callback with invalid state.
	t.Run("invalid state returns error", func(t *testing.T) {
		values := url.Values{}
		values.Set("code", "some-code")
		values.Set("state", "invalid-state-token")

		_, err := a.ValidateOIDCAuthCallback(ctx, values)
		require.Error(t, err)
	})
}
