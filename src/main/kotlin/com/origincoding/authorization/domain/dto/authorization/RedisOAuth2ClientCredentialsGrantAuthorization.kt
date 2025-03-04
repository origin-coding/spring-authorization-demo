package com.origincoding.authorization.domain.dto.authorization

import com.origincoding.authorization.domain.dto.token.AccessToken
import com.origincoding.authorization.domain.dto.token.RefreshToken

open class RedisOAuth2ClientCredentialsGrantAuthorization(
    id: String,
    registeredClientId: String,
    principalName: String,
    authorizedScopes: Set<String>?,
    accessToken: AccessToken?,
    refreshToken: RefreshToken?,
) : RedisOAuth2AuthorizationGrantAuthorization(
    id,
    registeredClientId,
    principalName,
    authorizedScopes,
    accessToken,
    refreshToken
)
