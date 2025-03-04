package com.origincoding.authorization.domain.dto.token

class ClaimsHolder(private val claims: Map<String, Any>?) {
    fun getClaims(): Map<String, Any>? = claims
}
