package com.origincoding.authorization.domain.dto

import org.springframework.data.annotation.Id
import org.springframework.data.redis.core.RedisHash
import org.springframework.data.redis.core.index.Indexed
import org.springframework.security.core.GrantedAuthority

@RedisHash("redis_oauth2_authorization_consent")
data class RedisOAuth2AuthorizationConsent(
    @Id val id: String,

    @Indexed val registeredClientId: String,

    @Indexed val principalName: String,

    val authorities: Set<GrantedAuthority>,
)
