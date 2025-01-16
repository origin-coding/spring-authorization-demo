package com.origincoding.authorization.domain.dto

import org.springframework.data.annotation.Id
import org.springframework.data.redis.core.RedisHash
import org.springframework.data.redis.core.index.Indexed
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import java.time.Duration
import java.time.Instant

@RedisHash("OAuth2RegisteredClient")
data class RedisRegisteredClient(
    @Id
    val id: String,
    @Indexed
    val clientId: String,
    val clientIdIssuedAt: Instant?,
    val clientSecret: String?,
    val clientSecretExpiresAt: Instant?,
    val clientName: String,
    val clientAuthenticationMethods: Set<ClientAuthenticationMethod>,
    val authorizationGrantTypes: Set<AuthorizationGrantType>,
    val redirectUris: Set<String>,
    val postLogoutRedirectUris: Set<String>,
    val scopes: Set<String>,
    val clientSettings: ClientSettings,
    val tokenSettings: TokenSettings
) {
    data class ClientSettings(
        val requireProofKey: Boolean,
        val requireAuthorizationConsent: Boolean,
        val jwkSetUrl: String?,
        val tokenEndpointAuthenticationSigningAlgorithm: JwsAlgorithm?,
        val x509CertificateSubjectDN: String?
    )

    data class TokenSettings(
        val authorizationCodeTimeToLive: Duration,
        val accessTokenTimeToLive: Duration,
        val accessTokenFormat: OAuth2TokenFormat,
        val deviceCodeTimeToLive: Duration,
        val reuseRefreshTokens: Boolean,
        val refreshTokenTimeToLive: Duration,
        val idTokenSignatureAlgorithm: SignatureAlgorithm,
        val x509CertificateBoundAccessTokens: Boolean
    )
}