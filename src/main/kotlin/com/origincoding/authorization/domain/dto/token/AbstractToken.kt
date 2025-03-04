package com.origincoding.authorization.domain.dto.token

import org.springframework.data.redis.core.index.Indexed
import java.time.Instant

open class AbstractToken(
    @Indexed
    val tokenValue: String,
    val issuedAt: Instant?,
    val expiresAt: Instant?,
    val invalidated: Boolean
)
