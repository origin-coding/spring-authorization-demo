package com.origincoding.authorization.service

import com.origincoding.authorization.converter.mapOAuth2AuthorizationGrantAuthorization
import com.origincoding.authorization.converter.toRedisOAuth2AuthorizationGrantAuthorization
import com.origincoding.authorization.domain.dto.RedisOAuth2AuthorizationGrantAuthorization
import com.origincoding.authorization.repository.RedisOAuth2AuthorizationGrantAuthorizationRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.stereotype.Service
import org.springframework.util.Assert

@Service
class RedisOAuth2AuthorizationService(
    private val registeredClientRepository: RegisteredClientRepository,
    private val redisOAuth2AuthorizationGrantAuthorizationRepository: RedisOAuth2AuthorizationGrantAuthorizationRepository
) : OAuth2AuthorizationService {
    override fun save(authorization: OAuth2Authorization) {
        redisOAuth2AuthorizationGrantAuthorizationRepository.save(authorization.toRedisOAuth2AuthorizationGrantAuthorization())
    }

    override fun remove(authorization: OAuth2Authorization) {
        redisOAuth2AuthorizationGrantAuthorizationRepository.deleteById(authorization.id)
    }

    override fun findById(id: String): OAuth2Authorization? {
        Assert.hasText(id) { "id cannot be empty" }
        return redisOAuth2AuthorizationGrantAuthorizationRepository.findById(id)
            .map { toOAuth2Authorization(it) }
            .orElse(null)
    }

    override fun findByToken(token: String, tokenType: OAuth2TokenType?): OAuth2Authorization? {
        Assert.hasText(token) { "token cannot be empty" }

        var authorizationGrantAuthorization: RedisOAuth2AuthorizationGrantAuthorization? = null

        if (tokenType == null) {
            authorizationGrantAuthorization =
                redisOAuth2AuthorizationGrantAuthorizationRepository.findByStateOrAuthorizationCode_TokenValue(
                    token,
                    token
                )
            if (authorizationGrantAuthorization == null) {
                authorizationGrantAuthorization =
                    redisOAuth2AuthorizationGrantAuthorizationRepository.findByAccessToken_TokenValueOrRefreshToken_TokenValue(
                        token,
                        token
                    )
            }
            if (authorizationGrantAuthorization == null) {
                authorizationGrantAuthorization =
                    redisOAuth2AuthorizationGrantAuthorizationRepository.findByIdToken_TokenValue(token)
            }
        } else if (OAuth2ParameterNames.STATE == tokenType.value) {
            authorizationGrantAuthorization =
                redisOAuth2AuthorizationGrantAuthorizationRepository.findByState(token)
        } else if (OAuth2ParameterNames.CODE == tokenType.value) {
            authorizationGrantAuthorization =
                redisOAuth2AuthorizationGrantAuthorizationRepository.findByAuthorizationCode_TokenValue(token)
        } else if (OAuth2ParameterNames.ACCESS_TOKEN == tokenType.value) {
            authorizationGrantAuthorization =
                redisOAuth2AuthorizationGrantAuthorizationRepository.findByAccessToken_TokenValue(token)
        } else if (OAuth2ParameterNames.REFRESH_TOKEN == tokenType.value) {
            authorizationGrantAuthorization =
                redisOAuth2AuthorizationGrantAuthorizationRepository.findByRefreshToken_TokenValue(token)
        } else if (OidcParameterNames.ID_TOKEN == tokenType.value) {
            authorizationGrantAuthorization =
                redisOAuth2AuthorizationGrantAuthorizationRepository.findByIdToken_TokenValue(token)
        }

        return authorizationGrantAuthorization?.let { toOAuth2Authorization(it) }
    }

    private fun toOAuth2Authorization(authorizationGrantAuthorization: RedisOAuth2AuthorizationGrantAuthorization): OAuth2Authorization {
        val registeredClient = registeredClientRepository.findById(authorizationGrantAuthorization.registeredClientId)
        val builder = OAuth2Authorization.withRegisteredClient(registeredClient)
        mapOAuth2AuthorizationGrantAuthorization(authorizationGrantAuthorization, builder)
        return builder.build()
    }
}