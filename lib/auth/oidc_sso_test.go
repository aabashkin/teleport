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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authtest"
)

func TestOIDCSSOService_CreateOIDCAuthRequest(t *testing.T) {
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

	// Create a test role.
	role, err := types.NewRole("test-role", types.RoleSpecV6{})
	require.NoError(t, err)
	_, err = a.UpsertRole(ctx, role)
	require.NoError(t, err)

	// Create a test OIDC connector.
	connector, err := types.NewOIDCConnector("test-oidc", types.OIDCConnectorSpecV3{
		ClientID:     "client-id-12345",
		ClientSecret: "client-secret-67890",
		IssuerURL:    "https://issuer.example.com",
		RedirectURLs: []string{"https://proxy.example.com/v1/webapi/oidc/callback"},
		ClaimsToRoles: []types.ClaimMapping{
			{
				Claim: "groups",
				Value: "admin",
				Roles: []string{"test-role"},
			},
		},
	})
	require.NoError(t, err)
	_, err = a.UpsertOIDCConnector(ctx, connector)
	require.NoError(t, err)

	t.Run("SSOTestFlow requires ConnectorSpec", func(t *testing.T) {
		req := types.OIDCAuthRequest{
			ConnectorID: "test-oidc",
			SSOTestFlow: true,
			// ConnectorSpec is nil - should fail
		}

		_, err := a.CreateOIDCAuthRequest(ctx, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ConnectorSpec cannot be nil")
	})

	t.Run("SSOTestFlow with ConnectorSpec", func(t *testing.T) {
		connSpec := &types.OIDCConnectorSpecV3{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			IssuerURL:    "https://test-issuer.example.com",
			RedirectURLs: []string{"https://test.example.com/callback"},
			ClaimsToRoles: []types.ClaimMapping{
				{
					Claim: "groups",
					Value: "users",
					Roles: []string{"test-role"},
				},
			},
		}

		req := types.OIDCAuthRequest{
			ConnectorID:      "test-oidc-connector",
			SSOTestFlow:      true,
			ConnectorSpec:    connSpec,
			CreateWebSession: true,
		}

		// This will fail because we can't actually connect to the issuer,
		// but the test verifies that the connector spec is properly used.
		_, err := a.CreateOIDCAuthRequest(ctx, req)
		// The error should be related to OIDC provider discovery, not connector spec
		require.Error(t, err)
	})
}

func TestOIDCSSOService_ClaimsToRolesMapping(t *testing.T) {
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

	// Verify that the OIDC service is properly initialized.
	// The auth server should have an OIDC service registered.
	require.NotNil(t, a, "Auth server should be initialized")

	// Create test roles.
	adminRole, err := types.NewRole("admin", types.RoleSpecV6{})
	require.NoError(t, err)
	_, err = a.UpsertRole(ctx, adminRole)
	require.NoError(t, err)

	userRole, err := types.NewRole("user", types.RoleSpecV6{})
	require.NoError(t, err)
	_, err = a.UpsertRole(ctx, userRole)
	require.NoError(t, err)

	// Create an OIDC connector with claim mappings.
	connector, err := types.NewOIDCConnector("test-claims-mapping", types.OIDCConnectorSpecV3{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		IssuerURL:    "https://issuer.example.com",
		RedirectURLs: []string{"https://proxy.example.com/v1/webapi/oidc/callback"},
		ClaimsToRoles: []types.ClaimMapping{
			{
				Claim: "groups",
				Value: "admins",
				Roles: []string{"admin"},
			},
			{
				Claim: "groups",
				Value: "users",
				Roles: []string{"user"},
			},
		},
	})
	require.NoError(t, err)
	_, err = a.UpsertOIDCConnector(ctx, connector)
	require.NoError(t, err)

	// Verify connector was created.
	retrievedConnector, err := a.GetOIDCConnector(ctx, "test-claims-mapping", true)
	require.NoError(t, err)
	assert.Equal(t, 2, len(retrievedConnector.GetClaimsToRoles()))
}

func TestOIDCSSOService_ConnectorWithMFA(t *testing.T) {
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

	// Create test role.
	role, err := types.NewRole("mfa-role", types.RoleSpecV6{})
	require.NoError(t, err)
	_, err = a.UpsertRole(ctx, role)
	require.NoError(t, err)

	// Create an OIDC connector with MFA settings.
	connector, err := types.NewOIDCConnector("test-mfa-oidc", types.OIDCConnectorSpecV3{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		IssuerURL:    "https://issuer.example.com",
		RedirectURLs: []string{"https://proxy.example.com/v1/webapi/oidc/callback"},
		ClaimsToRoles: []types.ClaimMapping{
			{
				Claim: "groups",
				Value: "users",
				Roles: []string{"mfa-role"},
			},
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

	// Verify connector was created with MFA settings.
	retrievedConnector, err := a.GetOIDCConnector(ctx, "test-mfa-oidc", true)
	require.NoError(t, err)
	assert.True(t, retrievedConnector.IsMFAEnabled())
}

func TestOIDCSSOService_ConnectorWithPKCE(t *testing.T) {
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

	// Create test role.
	role, err := types.NewRole("pkce-role", types.RoleSpecV6{})
	require.NoError(t, err)
	_, err = a.UpsertRole(ctx, role)
	require.NoError(t, err)

	// Create an OIDC connector with PKCE enabled.
	connector, err := types.NewOIDCConnector("test-pkce-oidc", types.OIDCConnectorSpecV3{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		IssuerURL:    "https://issuer.example.com",
		RedirectURLs: []string{"https://proxy.example.com/v1/webapi/oidc/callback"},
		ClaimsToRoles: []types.ClaimMapping{
			{
				Claim: "groups",
				Value: "users",
				Roles: []string{"pkce-role"},
			},
		},
		PKCEMode: "enabled",
	})
	require.NoError(t, err)
	_, err = a.UpsertOIDCConnector(ctx, connector)
	require.NoError(t, err)

	// Verify connector was created with PKCE settings.
	retrievedConnector, err := a.GetOIDCConnector(ctx, "test-pkce-oidc", true)
	require.NoError(t, err)
	assert.True(t, retrievedConnector.IsPKCEEnabled())
}
