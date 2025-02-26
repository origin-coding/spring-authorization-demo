package com.origincoding.authorization.domain.dto

open class RedisOAuth2ClientCredentialsGrantAuthorization(
    id: String,
    registeredClientId: String,
    principalName: String,
    authorizedScopes: Set<String>,
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
