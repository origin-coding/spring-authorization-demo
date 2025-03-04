package com.origincoding.authorization.domain.dto.authorization

import com.origincoding.authorization.domain.dto.token.AccessToken
import com.origincoding.authorization.domain.dto.token.AuthorizationCode
import com.origincoding.authorization.domain.dto.token.IdToken
import com.origincoding.authorization.domain.dto.token.RefreshToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import java.security.Principal

open class RedisOidcAuthorizationCodeGrantAuthorization(
    id: String,
    registeredClientId: String,
    principalName: String,
    authorizedScopes: Set<String>?,
    accessToken: AccessToken?,
    refreshToken: RefreshToken?,
    principal: Principal,
    authorizationRequest: OAuth2AuthorizationRequest,
    authorizationCode: AuthorizationCode?,
    state: String?,
    val idToken: IdToken?
) : RedisOAuth2AuthorizationCodeGrantAuthorization(
    id,
    registeredClientId,
    principalName,
    authorizedScopes,
    accessToken,
    refreshToken,
    principal,
    authorizationRequest,
    authorizationCode,
    state
)
