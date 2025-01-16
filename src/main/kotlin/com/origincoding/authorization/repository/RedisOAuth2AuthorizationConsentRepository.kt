package com.origincoding.authorization.repository

import com.origincoding.authorization.domain.dto.RedisOAuth2AuthorizationConsent
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository

@Repository
interface RedisOAuth2AuthorizationConsentRepository : CrudRepository<RedisOAuth2AuthorizationConsent, String> {
    fun findByRegisteredClientIdAndPrincipalName(registeredClientId: String, principalName: String): RedisOAuth2AuthorizationConsent?

    fun deleteByRegisteredClientIdAndPrincipalName(registeredClientId: String, principalName: String)
}