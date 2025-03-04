package com.origincoding.authorization.domain.dto.token

import java.time.Instant

class IdToken(
    tokenValue: String,
    issuedAt: Instant?,
    expiresAt: Instant?,
    invalidated: Boolean,
    val claims: ClaimsHolder
) : AbstractToken(tokenValue, issuedAt, expiresAt, invalidated)