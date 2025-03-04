package com.origincoding.authorization.domain.dto.token

import com.origincoding.authorization.domain.dto.PASSWORD_GRANT_TYPE
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken

class PasswordGrantAuthenticationToken(
    client: Authentication,
    val parameters: Map<String, String>
) : OAuth2AuthorizationGrantAuthenticationToken(
    PASSWORD_GRANT_TYPE,
    client,
    parameters
)
