package com.origincoding.authorization.converter

import com.origincoding.authorization.domain.dto.RedisOAuth2AuthorizationConsent
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent

fun RedisOAuth2AuthorizationConsent.toOAuth2AuthorizationConsent(): OAuth2AuthorizationConsent {
    return OAuth2AuthorizationConsent.withId(registeredClientId, principalName)
        .authorities { it.addAll(authorities) }
        .build()
}

fun OAuth2AuthorizationConsent.toRedisOAuth2AuthorizationConsent(): RedisOAuth2AuthorizationConsent {
    return RedisOAuth2AuthorizationConsent(
        id = "$registeredClientId-$principalName",
        registeredClientId = registeredClientId,
        principalName = principalName,
        authorities = authorities
    )
}
