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

package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gravitational/trace"
	"golang.org/x/oauth2"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/api/utils/keys/hardwarekey"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/client/sso"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

// OIDCSSOService implements the OIDCService interface for OIDC SSO authentication.
type OIDCSSOService struct {
	server *Server
	logger *slog.Logger
}

// NewOIDCSSOService creates a new OIDC SSO service.
func NewOIDCSSOService(server *Server) *OIDCSSOService {
	return &OIDCSSOService{
		server: server,
		logger: server.logger.With(teleport.ComponentKey, "oidc"),
	}
}

// CreateOIDCAuthRequest creates a new OIDC authentication request.
func (s *OIDCSSOService) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	connector, err := s.getOIDCConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Requests for a web session originate from the proxy, so they are trusted.
	// Requests for a client session (as used by tsh login) need to be checked.
	if !req.CreateWebSession {
		ceremonyType := sso.CeremonyTypeLogin
		if req.SSOTestFlow {
			ceremonyType = sso.CeremonyTypeTest
		}

		if err := sso.ValidateClientRedirect(req.ClientRedirectURL, ceremonyType, connector.GetClientRedirectSettings()); err != nil {
			return nil, trace.Wrap(err, InvalidClientRedirectErrorMessage)
		}
	}

	// Generate state token for the request.
	stateToken, err := utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.StateToken = stateToken

	// Get the redirect URL based on the connector configuration.
	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Build the OAuth2 config for the OIDC provider.
	oauthConfig, err := s.buildOAuth2Config(ctx, connector, redirectURL)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Build authorization URL options.
	authOptions := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("state", stateToken),
	}

	// Add PKCE if enabled.
	if connector.IsPKCEEnabled() {
		verifier := oauth2.GenerateVerifier()
		req.PkceVerifier = verifier
		authOptions = append(authOptions, oauth2.S256ChallengeOption(verifier))
	}

	// Add prompt if configured.
	if prompt := connector.GetPrompt(); prompt != "" {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("prompt", prompt))
	}

	// Add ACR values if configured.
	if acr := connector.GetACR(); acr != "" {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("acr_values", acr))
	}

	// Add max_age if configured.
	if maxAge, ok := connector.GetMaxAge(); ok {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("max_age", fmt.Sprintf("%d", int(maxAge.Seconds()))))
	}

	// Add login_hint if provided.
	if req.LoginHint != "" {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("login_hint", req.LoginHint))
	}

	// Generate the authorization URL.
	req.RedirectURL = oauthConfig.AuthCodeURL(stateToken, authOptions...)

	s.logger.DebugContext(ctx, "Creating OIDC auth request",
		"connector", connector.GetName(),
		"redirect_url", req.RedirectURL,
	)

	// Store the request.
	if err := s.server.Services.CreateOIDCAuthRequest(ctx, req, defaults.OIDCAuthRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}

	return &req, nil
}

// CreateOIDCAuthRequestForMFA creates a new OIDC authentication request for MFA purposes.
func (s *OIDCSSOService) CreateOIDCAuthRequestForMFA(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	connector, err := s.getOIDCConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if !connector.IsMFAEnabled() {
		return nil, trace.BadParameter("OIDC connector %q does not have MFA enabled", req.ConnectorID)
	}

	// Apply MFA settings to the connector.
	if err := connector.WithMFASettings(); err != nil {
		return nil, trace.Wrap(err)
	}

	// Generate state token.
	stateToken, err := utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.StateToken = stateToken

	// Get the redirect URL.
	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Build OAuth2 config.
	oauthConfig, err := s.buildOAuth2Config(ctx, connector, redirectURL)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Build authorization URL options.
	authOptions := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("state", stateToken),
	}

	// Add PKCE if enabled.
	if connector.IsPKCEEnabled() {
		verifier := oauth2.GenerateVerifier()
		req.PkceVerifier = verifier
		authOptions = append(authOptions, oauth2.S256ChallengeOption(verifier))
	}

	// Add prompt.
	if prompt := connector.GetPrompt(); prompt != "" {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("prompt", prompt))
	}

	// Add ACR values.
	if acr := connector.GetACR(); acr != "" {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("acr_values", acr))
	}

	// Add max_age for MFA.
	if maxAge, ok := connector.GetMaxAge(); ok {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("max_age", fmt.Sprintf("%d", int(maxAge.Seconds()))))
	}

	// Generate authorization URL.
	req.RedirectURL = oauthConfig.AuthCodeURL(stateToken, authOptions...)

	s.logger.DebugContext(ctx, "Creating OIDC auth request for MFA",
		"connector", connector.GetName(),
		"redirect_url", req.RedirectURL,
	)

	// Store request.
	if err := s.server.Services.CreateOIDCAuthRequest(ctx, req, defaults.OIDCAuthRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}

	return &req, nil
}

// ValidateOIDCAuthCallback validates the OIDC authentication callback.
func (s *OIDCSSOService) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*authclient.OIDCAuthResponse, error) {
	diagCtx := NewSSODiagContext(types.KindOIDC, s.server)

	event := &apievents.UserLogin{
		Metadata: apievents.Metadata{
			Type: events.UserLoginEvent,
		},
		Method:             events.LoginMethodOIDC,
		ConnectionMetadata: authz.ConnectionMetadata(ctx),
	}

	auth, err := s.validateOIDCAuthCallback(ctx, diagCtx, q)
	diagCtx.Info.Error = trace.UserMessage(err)

	diagCtx.WriteToBackend(ctx)

	if err != nil {
		event.Code = events.UserSSOLoginFailureCode
		if diagCtx.Info.TestFlow {
			event.Code = events.UserSSOTestFlowLoginFailureCode
		}
		event.Status.Success = false
		event.Status.Error = trace.Unwrap(err).Error()
		event.Status.UserMessage = err.Error()

		if emitErr := s.server.emitter.EmitAuditEvent(ctx, event); emitErr != nil {
			s.logger.WarnContext(ctx, "Failed to emit OIDC login failed event", "error", emitErr)
		}
		return nil, trace.Wrap(err)
	}

	event.Code = events.UserSSOLoginCode
	if diagCtx.Info.TestFlow {
		event.Code = events.UserSSOTestFlowLoginCode
	}
	event.Status.Success = true
	event.User = auth.Username

	if emitErr := s.server.emitter.EmitAuditEvent(ctx, event); emitErr != nil {
		s.logger.WarnContext(ctx, "Failed to emit OIDC login event", "error", emitErr)
	}

	return auth, nil
}

// validateOIDCAuthCallback performs the actual validation of the OIDC callback.
func (s *OIDCSSOService) validateOIDCAuthCallback(ctx context.Context, diagCtx *SSODiagContext, q url.Values) (*authclient.OIDCAuthResponse, error) {
	// Check for error from the IdP.
	if errParam := q.Get("error"); errParam != "" {
		state := q.Get("state")
		if state != "" {
			diagCtx.RequestID = state
			req, err := s.server.Services.GetOIDCAuthRequest(ctx, state)
			if err == nil {
				diagCtx.Info.TestFlow = req.SSOTestFlow
			}
		}

		errDesc := q.Get("error_description")
		oauthErr := trace.OAuth2("invalid_request", errParam, q)
		return nil, trace.WithUserMessage(oauthErr, "OIDC provider returned error: %v [%v]", errDesc, errParam)
	}

	// Get the authorization code.
	code := q.Get("code")
	if code == "" {
		oauthErr := trace.OAuth2("invalid_request", "code query param must be set", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from OIDC provider.")
	}

	// Get the state token.
	stateToken := q.Get("state")
	if stateToken == "" {
		oauthErr := trace.OAuth2("invalid_request", "missing state query param", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from OIDC provider.")
	}
	diagCtx.RequestID = stateToken

	// Get the stored auth request.
	req, err := s.server.Services.GetOIDCAuthRequest(ctx, stateToken)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC auth request.")
	}
	diagCtx.Info.TestFlow = req.SSOTestFlow

	// Get the OIDC connector.
	connector, err := s.getOIDCConnector(ctx, *req)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get OIDC connector.")
	}

	s.logger.DebugContext(ctx, "Processing OIDC callback",
		"connector", connector.GetName(),
		"state_token", stateToken,
	)

	// Get the redirect URL.
	redirectURL, err := services.GetRedirectURL(connector, req.ProxyAddress)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Build OAuth2 config.
	oauthConfig, err := s.buildOAuth2Config(ctx, connector, redirectURL)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Exchange the authorization code for tokens.
	exchangeOptions := []oauth2.AuthCodeOption{}
	if connector.IsPKCEEnabled() && req.PkceVerifier != "" {
		exchangeOptions = append(exchangeOptions, oauth2.VerifierOption(req.PkceVerifier))
	}

	token, err := oauthConfig.Exchange(ctx, code, exchangeOptions...)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to exchange authorization code for token.")
	}

	// Extract the ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, trace.BadParameter("no id_token in token response")
	}

	// Verify the ID token.
	idToken, claims, err := s.verifyIDToken(ctx, connector, rawIDToken)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to verify ID token.")
	}

	// Verify email is verified (unless explicitly allowed).
	if !connector.GetAllowUnverifiedEmail() {
		emailVerified, ok := claims["email_verified"]
		if !ok {
			return nil, trace.AccessDenied("OIDC provider did not provide email_verified claim.")
		}
		if verified, ok := emailVerified.(bool); !ok || !verified {
			return nil, trace.AccessDenied("OIDC provider did not verify email.")
		}
	}

	// Get the username from claims.
	username, err := s.getUsername(connector, claims)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to determine username from claims.")
	}

	s.logger.DebugContext(ctx, "OIDC authentication successful",
		"connector", connector.GetName(),
		"username", username,
		"subject", idToken.Subject,
	)

	// Map claims to roles and traits.
	params, err := s.calculateOIDCUser(ctx, diagCtx, connector, claims, username, req)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to calculate user attributes.")
	}

	diagCtx.Info.CreateUserParams = &types.CreateUserParams{
		ConnectorName: params.ConnectorName,
		Username:      params.Username,
		KubeGroups:    params.KubeGroups,
		KubeUsers:     params.KubeUsers,
		Roles:         params.Roles,
		Traits:        params.Traits,
		SessionTTL:    types.Duration(params.SessionTTL),
	}

	// Create or update the user.
	user, err := s.createOIDCUser(ctx, params, req.SSOTestFlow)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to create user from provided parameters.")
	}

	if err := s.server.CallLoginHooks(ctx, user); err != nil {
		return nil, trace.Wrap(err)
	}

	userState, err := s.server.GetUserOrLoginState(ctx, user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// In test flow, skip signing and creating web sessions.
	if req.SSOTestFlow {
		diagCtx.Info.Success = true
		return &authclient.OIDCAuthResponse{
			Req:      s.oidcAuthRequestFromProto(req),
			Identity: s.makeExternalIdentity(connector.GetName(), idToken.Subject, username),
			Username: params.Username,
		}, nil
	}

	// Return the auth response with session and certificates.
	return s.makeOIDCAuthResponse(ctx, req, userState, connector.GetName(), idToken.Subject, username, params.SessionTTL)
}

// getOIDCConnector retrieves the OIDC connector for the given request.
func (s *OIDCSSOService) getOIDCConnector(ctx context.Context, req types.OIDCAuthRequest) (types.OIDCConnector, error) {
	if req.SSOTestFlow {
		if req.ConnectorSpec == nil {
			return nil, trace.BadParameter("ConnectorSpec cannot be nil for SSOTestFlow")
		}

		if req.ConnectorID == "" {
			return nil, trace.BadParameter("ConnectorID cannot be empty")
		}

		connector, err := types.NewOIDCConnector(req.ConnectorID, *req.ConnectorSpec)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return connector, nil
	}

	connector, err := s.server.GetOIDCConnector(ctx, req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return connector, nil
}

// buildOAuth2Config creates an OAuth2 configuration for the OIDC connector.
func (s *OIDCSSOService) buildOAuth2Config(ctx context.Context, connector types.OIDCConnector, redirectURL string) (*oauth2.Config, error) {
	// Create the OIDC provider.
	provider, err := oidc.NewProvider(ctx, connector.GetIssuerURL())
	if err != nil {
		return nil, trace.Wrap(err, "Failed to create OIDC provider.")
	}

	// Build scopes.
	scopes := []string{oidc.ScopeOpenID}
	if additionalScopes := connector.GetScope(); len(additionalScopes) > 0 {
		scopes = append(scopes, additionalScopes...)
	} else {
		// Default scopes if not specified.
		scopes = append(scopes, "profile", "email")
	}

	return &oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     provider.Endpoint(),
	}, nil
}

// verifyIDToken verifies and parses the ID token.
func (s *OIDCSSOService) verifyIDToken(ctx context.Context, connector types.OIDCConnector, rawIDToken string) (*oidc.IDToken, map[string]interface{}, error) {
	provider, err := oidc.NewProvider(ctx, connector.GetIssuerURL())
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: connector.GetClientID(),
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, nil, trace.Wrap(err)
	}

	return idToken, claims, nil
}

// getUsername determines the username from the OIDC claims.
func (s *OIDCSSOService) getUsername(connector types.OIDCConnector, claims map[string]interface{}) (string, error) {
	// Check if a custom username claim is specified.
	if usernameClaim := connector.GetUsernameClaim(); usernameClaim != "" {
		username, ok := claims[usernameClaim].(string)
		if !ok || username == "" {
			return "", trace.BadParameter("username claim %q not found or empty in OIDC claims", usernameClaim)
		}
		return username, nil
	}

	// Try common username claims in order of preference.
	for _, claim := range []string{"preferred_username", "email", "name", "sub"} {
		if username, ok := claims[claim].(string); ok && username != "" {
			return username, nil
		}
	}

	return "", trace.BadParameter("could not determine username from OIDC claims")
}

// calculateOIDCUser calculates user parameters from OIDC claims.
func (s *OIDCSSOService) calculateOIDCUser(ctx context.Context, diagCtx *SSODiagContext, connector types.OIDCConnector, claims map[string]interface{}, username string, req *types.OIDCAuthRequest) (*CreateUserParams, error) {
	p := CreateUserParams{
		ConnectorName: connector.GetName(),
		Username:      username,
	}

	// Extract subject as UserID.
	if sub, ok := claims["sub"].(string); ok {
		p.UserID = sub
	}

	// Map claims to roles using the connector's claim mappings.
	p.Roles, p.KubeGroups, p.KubeUsers = s.mapClaimsToRoles(connector, claims)
	if len(p.Roles) == 0 {
		return nil, trace.AccessDenied("user does not belong to any groups mapped to roles; the configuration may have typos")
	}

	// Build traits from claims.
	p.Traits = s.buildTraits(connector, claims, username)

	// Apply login rules.
	evaluationInput := &loginrule.EvaluationInput{
		Traits: p.Traits,
	}
	evaluationOutput, err := s.server.GetLoginRuleEvaluator().Evaluate(ctx, evaluationInput)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	p.Traits = evaluationOutput.Traits
	diagCtx.Info.AppliedLoginRules = evaluationOutput.AppliedRules

	// Update kube groups/users from potentially modified traits.
	p.KubeGroups = p.Traits[constants.TraitKubeGroups]
	p.KubeUsers = p.Traits[constants.TraitKubeUsers]

	// Calculate session TTL.
	roles, err := services.FetchRoles(p.Roles, s.server, p.Traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleTTL := roles.AdjustSessionTTL(apidefaults.MaxCertDuration)
	p.SessionTTL = utils.MinTTL(roleTTL, req.CertTTL)

	return &p, nil
}

// mapClaimsToRoles maps OIDC claims to Teleport roles.
func (s *OIDCSSOService) mapClaimsToRoles(connector types.OIDCConnector, claims map[string]interface{}) (roles []string, kubeGroups []string, kubeUsers []string) {
	for _, mapping := range connector.GetClaimsToRoles() {
		claimValue, ok := claims[mapping.Claim]
		if !ok {
			continue
		}

		// Handle both single values and arrays.
		var claimValues []string
		switch v := claimValue.(type) {
		case string:
			claimValues = []string{v}
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					claimValues = append(claimValues, str)
				}
			}
		default:
			continue
		}

		// Check if any claim value matches.
		for _, cv := range claimValues {
			matched, err := utils.SliceMatchesRegex(cv, []string{mapping.Value})
			if err != nil {
				s.logger.WarnContext(context.Background(), "Error matching claim value", "claim", mapping.Claim, "value", cv, "pattern", mapping.Value, "error", err)
				continue
			}
			if matched {
				roles = append(roles, mapping.Roles...)
			}
		}
	}

	return apiutils.Deduplicate(roles), kubeGroups, kubeUsers
}

// buildTraits builds user traits from OIDC claims.
func (s *OIDCSSOService) buildTraits(connector types.OIDCConnector, claims map[string]interface{}, username string) map[string][]string {
	traits := make(map[string][]string)

	// Add username as login trait.
	traits[constants.TraitLogins] = []string{username}

	// Extract groups/roles from claims for traits.
	for _, mapping := range connector.GetClaimsToRoles() {
		claimValue, ok := claims[mapping.Claim]
		if !ok {
			continue
		}

		var claimValues []string
		switch v := claimValue.(type) {
		case string:
			claimValues = []string{v}
		case []interface{}:
			for _, item := range v {
				if str, ok := item.(string); ok {
					claimValues = append(claimValues, str)
				}
			}
		}

		if len(claimValues) > 0 {
			existingValues := traits[mapping.Claim]
			traits[mapping.Claim] = apiutils.Deduplicate(append(existingValues, claimValues...))
		}
	}

	// Add email as a trait if available.
	if email, ok := claims["email"].(string); ok && email != "" {
		traits["email"] = []string{email}
	}

	return traits
}

// createOIDCUser creates or updates the user in the backend.
func (s *OIDCSSOService) createOIDCUser(ctx context.Context, p *CreateUserParams, dryRun bool) (types.User, error) {
	s.logger.DebugContext(ctx, "Generating dynamic OIDC identity",
		"connector_name", p.ConnectorName,
		"user_name", p.Username,
		"roles", p.Roles,
		"dry_run", dryRun,
	)

	expires := s.server.GetClock().Now().UTC().Add(p.SessionTTL)

	user := &types.UserV2{
		Kind:    types.KindUser,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      p.Username,
			Namespace: apidefaults.Namespace,
			Expires:   &expires,
		},
		Spec: types.UserSpecV2{
			Roles:  p.Roles,
			Traits: p.Traits,
			OIDCIdentities: []types.ExternalIdentity{{
				ConnectorID: p.ConnectorName,
				Username:    p.Username,
				UserID:      p.UserID,
			}},
			CreatedBy: types.CreatedBy{
				User: types.UserRef{Name: teleport.UserSystem},
				Time: s.server.GetClock().Now().UTC(),
				Connector: &types.ConnectorRef{
					Type:     constants.OIDC,
					ID:       p.ConnectorName,
					Identity: p.Username,
				},
			},
		},
	}

	if dryRun {
		return user, nil
	}

	existingUser, err := s.server.Services.GetUser(ctx, p.Username, false)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}

	if existingUser != nil {
		ref := user.GetCreatedBy().Connector
		if !ref.IsSameProvider(existingUser.GetCreatedBy().Connector) {
			return nil, trace.AlreadyExists("local user %q already exists and is not an OIDC user",
				existingUser.GetName())
		}

		user.SetRevision(existingUser.GetRevision())
		if _, err := s.server.UpdateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if _, err := s.server.CreateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return user, nil
}

// makeExternalIdentity creates an external identity from OIDC token info.
func (s *OIDCSSOService) makeExternalIdentity(connectorID, subject, username string) types.ExternalIdentity {
	return types.ExternalIdentity{
		ConnectorID: connectorID,
		Username:    username,
	}
}

// oidcAuthRequestFromProto converts the types.OIDCAuthRequest to authclient.OIDCAuthRequest.
func (s *OIDCSSOService) oidcAuthRequestFromProto(req *types.OIDCAuthRequest) authclient.OIDCAuthRequest {
	return authclient.OIDCAuthRequest{
		ConnectorID:       req.ConnectorID,
		SSHPubKey:         req.SshPublicKey,
		TLSPubKey:         req.TlsPublicKey,
		CSRFToken:         req.CSRFToken,
		CreateWebSession:  req.CreateWebSession,
		ClientRedirectURL: req.ClientRedirectURL,
	}
}

// makeOIDCAuthResponse builds the final authentication response.
func (s *OIDCSSOService) makeOIDCAuthResponse(
	ctx context.Context,
	req *types.OIDCAuthRequest,
	userState services.UserState,
	connectorID, subject, username string,
	sessionTTL time.Duration,
) (*authclient.OIDCAuthResponse, error) {
	auth := authclient.OIDCAuthResponse{
		Req:      s.oidcAuthRequestFromProto(req),
		Identity: s.makeExternalIdentity(connectorID, subject, username),
		Username: userState.GetName(),
	}

	// If the request is coming from a browser, create a web session.
	if req.CreateWebSession {
		session, err := s.server.CreateWebSessionFromReq(ctx, NewWebSessionRequest{
			User:                 userState.GetName(),
			Roles:                userState.GetRoles(),
			Traits:               userState.GetTraits(),
			SessionTTL:           sessionTTL,
			LoginTime:            s.server.clock.Now().UTC(),
			LoginIP:              req.ClientLoginIP,
			LoginUserAgent:       req.ClientUserAgent,
			AttestWebSession:     true,
			CreateDeviceWebToken: true,
			Scope:                req.Scope,
		})
		if err != nil {
			return nil, trace.Wrap(err, "Failed to create web session.")
		}

		auth.Session = session
	}

	// If a public key was provided, sign it and return a certificate.
	if len(req.SshPublicKey) != 0 || len(req.TlsPublicKey) != 0 {
		sshCert, tlsCert, err := s.server.CreateSessionCerts(ctx, &SessionCertsRequest{
			UserState:               userState,
			SessionTTL:              sessionTTL,
			SSHPubKey:               req.SshPublicKey,
			TLSPubKey:               req.TlsPublicKey,
			SSHAttestationStatement: hardwarekey.AttestationStatementFromProto(req.SshAttestationStatement),
			TLSAttestationStatement: hardwarekey.AttestationStatementFromProto(req.TlsAttestationStatement),
			Compatibility:           req.Compatibility,
			RouteToCluster:          req.RouteToCluster,
			KubernetesCluster:       req.KubernetesCluster,
			LoginIP:                 req.ClientLoginIP,
			Scope:                   req.Scope,
		})
		if err != nil {
			return nil, trace.Wrap(err, "Failed to create session certificate.")
		}

		clusterName, err := s.server.GetClusterName(ctx)
		if err != nil {
			return nil, trace.Wrap(err, "Failed to obtain cluster name.")
		}

		auth.Cert = sshCert
		auth.TLSCert = tlsCert

		// Return the host CA for this cluster only.
		authority, err := s.server.GetCertAuthority(ctx, types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			return nil, trace.Wrap(err, "Failed to obtain cluster's host CA.")
		}
		auth.HostSigners = append(auth.HostSigners, authority)
	}

	if o, err := s.server.ClientOptionsForLogin(userState); err == nil {
		auth.ClientOptions = o
	} else {
		s.logger.WarnContext(ctx, "Failed to calculate client options for OIDC login", "username", userState.GetName(), "error", err)
	}

	return &auth, nil
}

// init registers the OIDC SSO service with the auth server.
func init() {
	// This function will be called to register the OIDC service.
	// The actual registration happens when the auth server is initialized.
}
