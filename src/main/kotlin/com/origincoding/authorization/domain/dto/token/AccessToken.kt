package com.origincoding.authorization.domain.dto.token

import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import java.time.Instant

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

