package com.origincoding.authorization.domain.dto.token

import java.time.Instant

class RefreshToken(
    tokenValue: String,
    issuedAt: Instant?,
    expiresAt: Instant?,
    invalidated: Boolean
) : AbstractToken(tokenValue, issuedAt, expiresAt, invalidated)
