package com.origincoding.authorization.converter

import com.origincoding.authorization.domain.dto.RedisRegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.util.CollectionUtils
import org.springframework.util.StringUtils

fun RegisteredClient.toRedisRegisteredClient(): RedisRegisteredClient {
    return RedisRegisteredClient(
        id = this.id,
        clientId = this.clientId,
        clientIdIssuedAt = this.clientIdIssuedAt,
        clientSecret = this.clientSecret,
        clientSecretExpiresAt = this.clientSecretExpiresAt,
        clientName = this.clientName,
        clientAuthenticationMethods = this.clientAuthenticationMethods,
        authorizationGrantTypes = this.authorizationGrantTypes,
        redirectUris = this.redirectUris,
        postLogoutRedirectUris = this.postLogoutRedirectUris,
        scopes = this.scopes,
        clientSettings = RedisRegisteredClient.ClientSettings(
            requireProofKey = this.clientSettings.isRequireProofKey,
            requireAuthorizationConsent = this.clientSettings.isRequireAuthorizationConsent,
            jwkSetUrl = this.clientSettings.jwkSetUrl,
            tokenEndpointAuthenticationSigningAlgorithm = this.clientSettings.tokenEndpointAuthenticationSigningAlgorithm,
            x509CertificateSubjectDN = this.clientSettings.x509CertificateSubjectDN
        ),
        tokenSettings = RedisRegisteredClient.TokenSettings(
            authorizationCodeTimeToLive = this.tokenSettings.authorizationCodeTimeToLive,
            accessTokenTimeToLive = this.tokenSettings.accessTokenTimeToLive,
            accessTokenFormat = this.tokenSettings.accessTokenFormat,
            deviceCodeTimeToLive = this.tokenSettings.deviceCodeTimeToLive,
            reuseRefreshTokens = this.tokenSettings.isReuseRefreshTokens,
            refreshTokenTimeToLive = this.tokenSettings.refreshTokenTimeToLive,
            idTokenSignatureAlgorithm = this.tokenSettings.idTokenSignatureAlgorithm,
            x509CertificateBoundAccessTokens = this.tokenSettings.isX509CertificateBoundAccessTokens
        )
    )
}

fun RedisRegisteredClient.toRegisteredClient(): RegisteredClient {
    val clientSettingsBuilder = ClientSettings.builder().requireProofKey(this.clientSettings.requireProofKey)
        .requireAuthorizationConsent(this.clientSettings.requireAuthorizationConsent)
    this.clientSettings.jwkSetUrl.takeIf(StringUtils::hasText)?.let { clientSettingsBuilder.jwkSetUrl(it) }
    this.clientSettings.tokenEndpointAuthenticationSigningAlgorithm?.let {
        clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(it)
    }
    this.clientSettings.x509CertificateSubjectDN.takeIf(StringUtils::hasText)
        ?.let { clientSettingsBuilder.x509CertificateSubjectDN(it) }
    val clientSettings = clientSettingsBuilder.build()

    val tokenSettingsBuilder = TokenSettings.builder()
    tokenSettingsBuilder.authorizationCodeTimeToLive(this.tokenSettings.authorizationCodeTimeToLive)
    tokenSettingsBuilder.accessTokenTimeToLive(this.tokenSettings.accessTokenTimeToLive)
    tokenSettingsBuilder.accessTokenFormat(this.tokenSettings.accessTokenFormat)
    tokenSettingsBuilder.deviceCodeTimeToLive(this.tokenSettings.deviceCodeTimeToLive)
    tokenSettingsBuilder.reuseRefreshTokens(this.tokenSettings.reuseRefreshTokens)
    tokenSettingsBuilder.refreshTokenTimeToLive(this.tokenSettings.refreshTokenTimeToLive)
    tokenSettingsBuilder.idTokenSignatureAlgorithm(this.tokenSettings.idTokenSignatureAlgorithm)
    tokenSettingsBuilder.x509CertificateBoundAccessTokens(this.tokenSettings.x509CertificateBoundAccessTokens)
    val tokenSettings = tokenSettingsBuilder.build()

    val registeredClientBuilder =
        RegisteredClient.withId(this.id).clientId(this.clientId).clientIdIssuedAt(this.clientIdIssuedAt)
            .clientSecret(this.clientSecret).clientSecretExpiresAt(this.clientSecretExpiresAt)
            .clientName(this.clientName).clientAuthenticationMethods {
                it.addAll(this.clientAuthenticationMethods)
            }.authorizationGrantTypes {
                it.addAll(this.authorizationGrantTypes)
            }.clientSettings(clientSettings).tokenSettings(tokenSettings)

    this.redirectUris.takeUnless(CollectionUtils::isEmpty)?.run {
        registeredClientBuilder.redirectUris { it.addAll(this) }
    }

    this.postLogoutRedirectUris.takeUnless(CollectionUtils::isEmpty)?.run {
        registeredClientBuilder.postLogoutRedirectUris { it.addAll(this) }
    }

    this.scopes.takeUnless(CollectionUtils::isEmpty)?.run {
        registeredClientBuilder.scopes { it.addAll(this) }
    }

    return registeredClientBuilder.build()
}

