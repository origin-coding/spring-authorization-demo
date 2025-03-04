package com.origincoding.authorization.domain.dto.authorization

import com.origincoding.authorization.domain.dto.token.AccessToken
import com.origincoding.authorization.domain.dto.token.AuthorizationCode
import com.origincoding.authorization.domain.dto.token.RefreshToken
import org.springframework.data.redis.core.index.Indexed
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import java.security.Principal

open class RedisOAuth2AuthorizationCodeGrantAuthorization(
    id: String,
    registeredClientId: String,
    principalName: String,
    authorizedScopes: Set<String>?,
    accessToken: AccessToken?,
    refreshToken: RefreshToken?,
    open val principal: Principal,
    open val authorizationRequest: OAuth2AuthorizationRequest,
    open val authorizationCode: AuthorizationCode?,
    @Indexed open val state: String? // Used to correlate the request during the authorization consent flow
) : RedisOAuth2AuthorizationGrantAuthorization(
    id,
    registeredClientId,
    principalName,
    authorizedScopes,
    accessToken,
    refreshToken
)
