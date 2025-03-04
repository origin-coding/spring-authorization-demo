package com.origincoding.authorization.domain.dto.authorization

import com.origincoding.authorization.domain.dto.token.AccessToken
import com.origincoding.authorization.domain.dto.token.RefreshToken
import org.springframework.data.annotation.Id
import org.springframework.data.redis.core.RedisHash

@RedisHash("oauth2_authorization")
open class RedisOAuth2AuthorizationGrantAuthorization(
    @Id
    val id: String,
    val registeredClientId: String,
    val principalName: String,
    val authorizedScopes: Set<String>?,
    val accessToken: AccessToken?,
    val refreshToken: RefreshToken?
)
