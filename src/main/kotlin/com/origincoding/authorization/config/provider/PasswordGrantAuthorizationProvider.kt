package com.origincoding.authorization.config.provider

import com.origincoding.authorization.domain.dto.token.PasswordGrantAuthenticationToken
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.util.StringUtils
import java.security.Principal

class PasswordGrantAuthenticationProvider(
    private val userDetailsService: UserDetailsService,
    private val passwordEncoder: PasswordEncoder,
    private val tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>,
    private val authorizationService: OAuth2AuthorizationService
) : AuthenticationProvider {
    // Kotlin Logging
    private val logger = KotlinLogging.logger {}

    override fun authenticate(authentication: Authentication): Authentication {
        val passwordGrantAuthenticationToken = authentication as PasswordGrantAuthenticationToken
        val additionalParameters = passwordGrantAuthenticationToken.parameters.toMutableMap()

        val authorizationGrantType = passwordGrantAuthenticationToken.grantType

        val clientPrincipal = getAuthenticatedClientOrThrow(passwordGrantAuthenticationToken)
        val registeredClient = clientPrincipal.registeredClient

        if (registeredClient?.authorizationGrantTypes?.contains(authorizationGrantType) != true) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
        }

        val username = additionalParameters[OAuth2ParameterNames.USERNAME]
        val password = additionalParameters[OAuth2ParameterNames.PASSWORD]
        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            throw OAuth2AuthenticationException("用户名或密码不能为空！")
        }

        val userDetails = userDetailsService.loadUserByUsername(username)
        if (!passwordEncoder.matches(password, userDetails.password)) {
            throw OAuth2AuthenticationException("用户名或密码错误！")
        }

        // 前面已经校验过密码，所以这里直接构造Authorization
        val usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken.authenticated(
            userDetails, clientPrincipal, userDetails.authorities
        )

        // 获取请求的Scope Set
        val scopes = additionalParameters[OAuth2ParameterNames.SCOPE]?.split(" ")?.toSet() ?: emptySet()

        val tokenContextBuilder = DefaultOAuth2TokenContext.builder().registeredClient(registeredClient)
            .principal(usernamePasswordAuthenticationToken)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizationGrantType(authorizationGrantType).authorizedScopes(scopes)
            .authorizationGrant(passwordGrantAuthenticationToken)

        val authorizationBuilder =
            OAuth2Authorization.withRegisteredClient(registeredClient).principalName(clientPrincipal.name)
                .authorizedScopes(scopes).attribute(Principal::class.java.name, usernamePasswordAuthenticationToken)
                .authorizationGrantType(authorizationGrantType)

        // Access Token

        val accessTokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build()
        val generatedAccessToken = tokenGenerator.generate(accessTokenContext) ?: throw OAuth2AuthenticationException(
            OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR, "生成AccessToken失败！", null
            )
        )
        logger.trace { "Generated access token" }

        val accessToken = OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.tokenValue,
            generatedAccessToken.issuedAt,
            generatedAccessToken.expiresAt,
            accessTokenContext.authorizedScopes
        )

        if (generatedAccessToken is ClaimAccessor) {
            authorizationBuilder.token(accessToken) {
                it[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = generatedAccessToken.claims
            }
        } else {
            authorizationBuilder.accessToken(accessToken)
        }

        // Refresh Token
        var refreshToken: OAuth2RefreshToken? = null
        if (registeredClient.authorizationGrantTypes.contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            val refreshTokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build()

            val generatedRefreshToken =
                tokenGenerator.generate(refreshTokenContext) ?: throw OAuth2AuthenticationException(
                    OAuth2Error(
                        OAuth2ErrorCodes.SERVER_ERROR, "生成RefreshToken失败！", null
                    )
                )
            if (generatedRefreshToken !is OAuth2RefreshToken) {
                throw OAuth2AuthenticationException(
                    OAuth2Error(
                        OAuth2ErrorCodes.SERVER_ERROR, "生成RefreshToken失败！", null
                    )
                )
            }

            logger.trace { "Generated refresh token" }

            refreshToken = generatedRefreshToken
            authorizationBuilder.refreshToken(refreshToken)
        }

        // Id Token
        var idToken: OAuth2Token? = null
        if (registeredClient.scopes.contains(OidcScopes.OPENID)) {
            val idTokenContext = tokenContextBuilder.tokenType(OAuth2TokenType(OidcParameterNames.ID_TOKEN))
                .authorization(authorizationBuilder.build())
                .build()
            val generatedIdToken = tokenGenerator.generate(idTokenContext)
            if (generatedIdToken !is Jwt) {
                throw OAuth2AuthenticationException(
                    OAuth2Error(
                        OAuth2ErrorCodes.SERVER_ERROR, "生成IdToken失败！", null
                    )
                )
            }

            logger.trace { "Generated id token" }

            idToken = OidcIdToken(
                generatedIdToken.tokenValue,
                generatedIdToken.issuedAt,
                generatedIdToken.expiresAt,
                generatedIdToken.claims
            )
            authorizationBuilder.token(idToken) {
                it[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = generatedIdToken.claims
            }
        }

        // 这里需要invalidate掉AuthorizationCode

        val authorization = authorizationBuilder.build()
        authorizationService.save(authorization)

        if (idToken != null) {
            additionalParameters[OidcParameterNames.ID_TOKEN] = idToken.tokenValue
        }

        return OAuth2AccessTokenAuthenticationToken(
            registeredClient,
            clientPrincipal,
            accessToken,
            refreshToken,
            additionalParameters as Map<String, Any>
        )
    }

    override fun supports(authentication: Class<*>): Boolean {
        return PasswordGrantAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

    private fun getAuthenticatedClientOrThrow(authentication: Authentication): OAuth2ClientAuthenticationToken {
        var clientPrincipal: OAuth2ClientAuthenticationToken? = null

        if (OAuth2ClientAuthenticationToken::class.java.isAssignableFrom(authentication.principal.javaClass)) {
            clientPrincipal = authentication.principal as OAuth2ClientAuthenticationToken
        }

        if (clientPrincipal != null && clientPrincipal.isAuthenticated) {
            return clientPrincipal
        }

        throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)
    }
}
