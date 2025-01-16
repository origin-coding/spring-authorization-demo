package com.origincoding.authorization.service

import com.origincoding.authorization.converter.toOAuth2AuthorizationConsent
import com.origincoding.authorization.converter.toRedisOAuth2AuthorizationConsent
import com.origincoding.authorization.repository.RedisOAuth2AuthorizationConsentRepository

import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.stereotype.Service
import org.springframework.util.Assert

@Service
class RedisOAuth2AuthorizationConsentService(
    private val repository: RedisOAuth2AuthorizationConsentRepository
) : OAuth2AuthorizationConsentService {
    override fun save(authorizationConsent: OAuth2AuthorizationConsent) {
        repository.save(authorizationConsent.toRedisOAuth2AuthorizationConsent())
    }

    override fun remove(authorizationConsent: OAuth2AuthorizationConsent) {
        repository.deleteByRegisteredClientIdAndPrincipalName(
            authorizationConsent.registeredClientId,
            authorizationConsent.principalName
        )
    }

    override fun findById(registeredClientId: String, principalName: String): OAuth2AuthorizationConsent? {
        Assert.hasText(registeredClientId) { "registeredClientId cannot be empty" }
        Assert.hasText(principalName) { "principalName cannot be empty" }
        return repository.findByRegisteredClientIdAndPrincipalName(registeredClientId, principalName)
            ?.toOAuth2AuthorizationConsent()
    }
}