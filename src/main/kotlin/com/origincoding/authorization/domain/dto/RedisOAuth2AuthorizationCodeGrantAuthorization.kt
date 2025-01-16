package com.origincoding.authorization.domain.dto

import org.springframework.data.redis.core.index.Indexed
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import java.security.Principal
import java.time.Instant

open class RedisOAuth2AuthorizationCodeGrantAuthorization(
    id: String,
    registeredClientId: String,
    principalName: String,
    authorizedScopes: Set<String>,
    accessToken: AccessToken?,
    refreshToken: RefreshToken?,
    open val principal: Principal,
    open val authorizationRequest: OAuth2AuthorizationRequest,
    open val authorizationCode: AuthorizationCode?,
    @Indexed open val state: String? // Used to correlate the request during the authorization consent flow
) : RedisOAuth2AuthorizationGrantAuthorization(
    id,
    registeredClientId,
    principalName,
    authorizedScopes,
    accessToken,
    refreshToken
) {

    class AuthorizationCode(
        tokenValue: String,
        issuedAt: Instant?,
        expiresAt: Instant?,
        invalidated: Boolean
    ) : AbstractToken(tokenValue, issuedAt, expiresAt, invalidated)
}