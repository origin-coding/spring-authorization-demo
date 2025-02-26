package com.origincoding.authorization.service

import com.origincoding.authorization.converter.toRedisRegisteredClient
import com.origincoding.authorization.converter.toRegisteredClient
import com.origincoding.authorization.repository.RedisRegisteredClientRepository
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.stereotype.Service
import org.springframework.util.Assert
import java.util.*

@Service
class RedisRegisteredClientService(
    private val repository: RedisRegisteredClientRepository
) : RegisteredClientRepository {
    init {
        val oidcClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("oidc-client")
            .clientSecret(BCryptPasswordEncoder().encode("secret"))
            .clientName("这是一个客户端")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
            .postLogoutRedirectUri("http://127.0.0.1:8080/").scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .build()

        // 如果有客户端，那么就不添加
        if (repository.findByClientId(oidcClient.clientId) == null) {
            repository.save(oidcClient.toRedisRegisteredClient())
        }
    }

    override fun save(registeredClient: RegisteredClient) {
        repository.save(registeredClient.toRedisRegisteredClient())
    }

    override fun findById(id: String): RegisteredClient? {
        Assert.hasText(id) { "id must not be empty" }
        return repository.findById(id).map { it.toRegisteredClient() }.orElse(null)
    }

    override fun findByClientId(clientId: String): RegisteredClient? {
        Assert.hasText(clientId) { "clientId must not be empty" }
        return repository.findByClientId(clientId)?.toRegisteredClient()
    }
}