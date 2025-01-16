package com.origincoding.authorization.domain.dto

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import java.security.Principal
import java.time.Instant

open class RedisOidcAuthorizationCodeGrantAuthorization(
    id: String,
    registeredClientId: String,
    principalName: String,
    authorizedScopes: Set<String>,
    accessToken: AccessToken?,
    refreshToken: RefreshToken?,
    principal: Principal,
    authorizationRequest: OAuth2AuthorizationRequest,
    authorizationCode: AuthorizationCode,
    state: String?,
    val idToken: IdToken?
) : RedisOAuth2AuthorizationCodeGrantAuthorization(
    id,
    registeredClientId,
    principalName,
    authorizedScopes,
    accessToken,
    refreshToken,
    principal,
    authorizationRequest,
    authorizationCode,
    state
) {
    class IdToken(
        tokenValue: String,
        issuedAt: Instant?,
        expiresAt: Instant?,
        invalidated: Boolean,
        val claims: ClaimsHolder
    ) : AbstractToken(tokenValue, issuedAt, expiresAt, invalidated)
}