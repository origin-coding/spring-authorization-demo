package com.origincoding.authorization.domain.dto

import org.springframework.security.oauth2.core.AuthorizationGrantType

// 密码模式，在 OAuth 2.1 中被废弃，但是这里重新实现
val PASSWORD_GRANT_TYPE = AuthorizationGrantType("password")
