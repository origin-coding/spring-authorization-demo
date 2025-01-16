package com.origincoding.authorization.domain.dto

import org.springframework.data.annotation.Id
import org.springframework.data.redis.core.RedisHash
import org.springframework.data.redis.core.index.Indexed
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import java.time.Instant

@RedisHash("oauth2_authorization")
open class RedisOAuth2AuthorizationGrantAuthorization(
    @Id
    val id: String,
    val registeredClientId: String,
    val principalName: String,
    val authorizedScopes: Set<String>,
    val accessToken: AccessToken?,
    val refreshToken: RefreshToken?
) {

    open class AbstractToken(
        @Indexed
        val tokenValue: String,
        val issuedAt: Instant?,
        val expiresAt: Instant?,
        val invalidated: Boolean
    )

    class ClaimsHolder(private val claims: Map<String, Any>?) {
        fun getClaims(): Map<String, Any>? = claims
    }

    class AccessToken(
        tokenValue: String,
        issuedAt: Instant?,
        expiresAt: Instant?,
        invalidated: Boolean,
        val tokenType: OAuth2AccessToken.TokenType,
        val scopes: Set<String>,
        val tokenFormat: OAuth2TokenFormat,
        val claims: ClaimsHolder
    ) : AbstractToken(tokenValue, issuedAt, expiresAt, invalidated)

    class RefreshToken(
        tokenValue: String,
        issuedAt: Instant?,
        expiresAt: Instant?,
        invalidated: Boolean
    ) : AbstractToken(tokenValue, issuedAt, expiresAt, invalidated)
}