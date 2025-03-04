package com.origincoding.authorization.domain.dto.authorization

import com.origincoding.authorization.domain.dto.token.AccessToken
import com.origincoding.authorization.domain.dto.token.IdToken
import com.origincoding.authorization.domain.dto.token.RefreshToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import java.security.Principal

class RedisOAuth2PasswordGrantAuthorization(
    id: String,
    registeredClientId: String,
    principalName: String,
    authorizedScopes: Set<String>?,
    accessToken: AccessToken?,
    refreshToken: RefreshToken?,
    val principal: Principal,
    val authorizationRequest: OAuth2AuthorizationRequest?,
    val idToken: IdToken?
) : RedisOAuth2AuthorizationGrantAuthorization(
    id,
    registeredClientId,
    principalName,
    authorizedScopes,
    accessToken,
    refreshToken
)
