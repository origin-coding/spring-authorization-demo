package com.origincoding.authorization.converter

import com.origincoding.authorization.domain.dto.*
import com.origincoding.authorization.domain.dto.authorization.*
import com.origincoding.authorization.domain.dto.token.*
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.util.StringUtils
import java.security.Principal

fun OAuth2Authorization.toRedisOAuth2AuthorizationGrantAuthorization(): RedisOAuth2AuthorizationGrantAuthorization {
    if (AuthorizationGrantType.AUTHORIZATION_CODE == this.authorizationGrantType) {
        val authorizationRequest: OAuth2AuthorizationRequest =
            this.getAttribute(OAuth2AuthorizationRequest::class.java.name)!!

        return if (authorizationRequest.scopes.contains(OidcScopes.OPENID)) this.toRedisOidcAuthorizationCodeGrantAuthorization()
        else this.toRedisOAuth2AuthorizationCodeGrantAuthorization()
    } else if (AuthorizationGrantType.CLIENT_CREDENTIALS == this.authorizationGrantType) {
        return this.toRedisOAuth2ClientCredentialsGrantAuthorization()
    } else if (PASSWORD_GRANT_TYPE == this.authorizationGrantType) {
        return this.toRedisOAuth2PasswordGrantAuthorization()
    }

    throw IllegalArgumentException("Unsupported authorization grant type: ${this.authorizationGrantType}")
}

fun OAuth2Authorization.toRedisOAuth2AuthorizationCodeGrantAuthorization(): RedisOAuth2AuthorizationCodeGrantAuthorization {
    val authorizationCode = this.extractAuthorizationCode()
    val accessToken = this.extractAccessToken()
    val refreshToken = this.extractRefreshToken()

    return RedisOAuth2AuthorizationCodeGrantAuthorization(
        this.id,
        this.registeredClientId,
        this.principalName,
        this.authorizedScopes,
        accessToken,
        refreshToken,
        this.getAttribute(Principal::class.java.name)!!,
        this.getAttribute(OAuth2AuthorizationRequest::class.java.name)!!,
        authorizationCode,
        this.getAttribute(OAuth2ParameterNames.STATE)!!
    )
}

fun OAuth2Authorization.toRedisOidcAuthorizationCodeGrantAuthorization(): RedisOidcAuthorizationCodeGrantAuthorization {
    val authorizationCode = this.extractAuthorizationCode()
    val accessToken = this.extractAccessToken()
    val refreshToken = this.extractRefreshToken()

    return RedisOidcAuthorizationCodeGrantAuthorization(
        this.id,
        this.registeredClientId,
        this.principalName,
        this.authorizedScopes,
        accessToken,
        refreshToken,
        this.getAttribute(Principal::class.java.name)!!,
        this.getAttribute(OAuth2AuthorizationRequest::class.java.name)!!,
        authorizationCode,
        this.getAttribute(OAuth2ParameterNames.STATE),
        this.extractIdToken()
    )
}

fun OAuth2Authorization.toRedisOAuth2PasswordGrantAuthorization(): RedisOAuth2PasswordGrantAuthorization {
    val accessToken = this.extractAccessToken()
    val refreshToken = this.extractRefreshToken()

    return RedisOAuth2PasswordGrantAuthorization(
        this.id,
        this.registeredClientId,
        this.principalName,
        this.authorizedScopes,
        accessToken,
        refreshToken,
        this.getAttribute(Principal::class.java.name)!!,
        this.getAttribute(OAuth2AuthorizationRequest::class.java.name),
        this.extractPasswordIdToken()
    )
}

fun OAuth2Authorization.toRedisOAuth2ClientCredentialsGrantAuthorization(): RedisOAuth2ClientCredentialsGrantAuthorization {
    val accessToken = this.extractAccessToken()
    val refreshToken = this.extractRefreshToken()

    return RedisOAuth2ClientCredentialsGrantAuthorization(
        this.id, this.registeredClientId, this.principalName, this.authorizedScopes, accessToken, refreshToken
    )
}

fun OAuth2Authorization.extractAuthorizationCode(): AuthorizationCode? =
    this.getToken(OAuth2AuthorizationCode::class.java)?.let {
        AuthorizationCode(
            it.token.tokenValue, it.token.issuedAt, it.token.expiresAt, it.isInvalidated
        )
    }

fun OAuth2Authorization.extractAccessToken(): AccessToken? {
    val tokenFormat = this.accessToken?.metadata?.get(OAuth2TokenFormat::class.java.name)?.let { format ->
        when (format) {
            OAuth2TokenFormat.SELF_CONTAINED.value -> OAuth2TokenFormat.SELF_CONTAINED
            OAuth2TokenFormat.REFERENCE.value -> OAuth2TokenFormat.REFERENCE
            else -> null
        }
    } ?: return null

    return this.accessToken?.let {
        AccessToken(
            it.token.tokenValue,
            it.token.issuedAt,
            it.token.expiresAt,
            it.isInvalidated,
            it.token.tokenType,
            it.token.scopes,
            tokenFormat,
            ClaimsHolder(it.claims)
        )
    }
}

fun OAuth2Authorization.extractRefreshToken(): RefreshToken? = this.refreshToken?.let {
    RefreshToken(
        it.token.tokenValue, it.token.issuedAt, it.token.expiresAt, it.isInvalidated
    )
}

fun OAuth2Authorization.extractIdToken(): IdToken? = this.getToken(OidcIdToken::class.java)?.let {
    IdToken(
        it.token.tokenValue, it.token.issuedAt, it.token.expiresAt, it.isInvalidated, ClaimsHolder(it.claims)
    )
}

fun OAuth2Authorization.extractPasswordIdToken(): IdToken? = this.getToken(OidcIdToken::class.java)?.let {
    IdToken(
        it.token.tokenValue, it.token.issuedAt, it.token.expiresAt, it.isInvalidated, ClaimsHolder(it.claims)
    )
}

fun mapOAuth2AuthorizationGrantAuthorization(
    authorizationGrantAuthorization: RedisOAuth2AuthorizationGrantAuthorization, builder: Builder
) {
    when (authorizationGrantAuthorization) {
        is RedisOidcAuthorizationCodeGrantAuthorization -> {
            mapOidcAuthorizationCodeGrantAuthorization(authorizationGrantAuthorization, builder)
        }

        is RedisOAuth2AuthorizationCodeGrantAuthorization -> {
            mapOAuth2AuthorizationCodeGrantAuthorization(authorizationGrantAuthorization, builder)
        }

        is RedisOAuth2ClientCredentialsGrantAuthorization -> {
            mapOAuth2ClientCredentialsGrantAuthorization(authorizationGrantAuthorization, builder)
        }

        is RedisOAuth2PasswordGrantAuthorization -> {
            mapOAuth2PasswordGrantAuthorization(authorizationGrantAuthorization, builder)
        }
    }
}

fun mapOidcAuthorizationCodeGrantAuthorization(
    authorizationGrantAuthorization: RedisOidcAuthorizationCodeGrantAuthorization, builder: Builder
) {
    mapOAuth2AuthorizationCodeGrantAuthorization(authorizationGrantAuthorization, builder)
    mapIdToken(authorizationGrantAuthorization.idToken, builder)
}

fun mapOAuth2PasswordGrantAuthorization(
    authorizationGrantAuthorization: RedisOAuth2PasswordGrantAuthorization, builder: Builder
) {
    builder.id(authorizationGrantAuthorization.id).principalName(authorizationGrantAuthorization.principalName)
        .authorizationGrantType(PASSWORD_GRANT_TYPE).authorizedScopes(authorizationGrantAuthorization.authorizedScopes)
        .attribute(Principal::class.java.name, authorizationGrantAuthorization.principal)
    if (authorizationGrantAuthorization.authorizationRequest != null) {
        builder.attribute(OAuth2AuthorizationRequest::class.java.name, authorizationGrantAuthorization.authorizationRequest)
    }

    mapAccessToken(authorizationGrantAuthorization.accessToken, builder)
    mapRefreshToken(authorizationGrantAuthorization.refreshToken, builder)
    mapPasswordIdToken(authorizationGrantAuthorization.idToken, builder)
}

fun mapOAuth2AuthorizationCodeGrantAuthorization(
    authorizationGrantAuthorization: RedisOAuth2AuthorizationCodeGrantAuthorization, builder: Builder
) {
    builder.id(authorizationGrantAuthorization.id).principalName(authorizationGrantAuthorization.principalName)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizedScopes(authorizationGrantAuthorization.authorizedScopes)
        .attribute(Principal::class.java.name, authorizationGrantAuthorization.principal)
        .attribute(OAuth2AuthorizationRequest::class.java.name, authorizationGrantAuthorization.authorizationRequest)

    if (StringUtils.hasText(authorizationGrantAuthorization.state)) {
        builder.attribute(OAuth2ParameterNames.STATE, authorizationGrantAuthorization.state)
    }

    mapAuthorizationCode(authorizationGrantAuthorization.authorizationCode, builder)
    mapAccessToken(authorizationGrantAuthorization.accessToken, builder)
    mapRefreshToken(authorizationGrantAuthorization.refreshToken, builder)
}

fun mapAuthorizationCode(
    authorizationCode: AuthorizationCode?, builder: Builder
) {
    if (authorizationCode == null) {
        return
    }

    val oauth2AuthorizationCode = OAuth2AuthorizationCode(
        authorizationCode.tokenValue, authorizationCode.issuedAt, authorizationCode.expiresAt
    )
    builder.token(oauth2AuthorizationCode) { metadata ->
        metadata[OAuth2Authorization.Token.INVALIDATED_METADATA_NAME] = authorizationCode.invalidated
    }
}

fun mapAccessToken(
    accessToken: AccessToken?, builder: Builder
) {
    if (accessToken == null) {
        return
    }

    val oauth2AccessToken = OAuth2AccessToken(
        accessToken.tokenType, accessToken.tokenValue, accessToken.issuedAt, accessToken.expiresAt, accessToken.scopes
    )

    builder.token(oauth2AccessToken) { metadata ->
        metadata[OAuth2Authorization.Token.INVALIDATED_METADATA_NAME] = accessToken.invalidated
        metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = accessToken.claims.getClaims()
        metadata[OAuth2TokenFormat::class.java.name] = accessToken.tokenFormat.value
    }
}

fun mapRefreshToken(
    refreshToken: RefreshToken?, builder: Builder
) {
    if (refreshToken == null) {
        return
    }

    val oauth2RefreshToken = OAuth2RefreshToken(
        refreshToken.tokenValue, refreshToken.issuedAt, refreshToken.expiresAt
    )

    builder.token(oauth2RefreshToken) { metadata ->
        metadata[OAuth2Authorization.Token.INVALIDATED_METADATA_NAME] = refreshToken.invalidated
    }
}

fun mapIdToken(idToken: IdToken?, builder: Builder) {
    if (idToken == null) {
        return
    }

    val oidcIdToken = OidcIdToken(
        idToken.tokenValue, idToken.issuedAt, idToken.expiresAt, idToken.claims.getClaims()!!
    )

    builder.token(oidcIdToken) { metadata ->
        metadata[OAuth2Authorization.Token.INVALIDATED_METADATA_NAME] = idToken.invalidated
        metadata[OAuth2Authorization.Token.CLAIMS_METADATA_NAME] = idToken.claims.getClaims()
    }
}

fun mapPasswordIdToken(idToken: IdToken?, builder: Builder) {
    if (idToken == null) {
        return
    }

    val oidcIdToken = OidcIdToken(
        idToken.tokenValue, idToken.issuedAt, idToken.expiresAt, idToken.claims.getClaims()!!
    )

    builder.token(oidcIdToken) { metadata ->
        metadata[OAuth2Authorization.Token.INVALIDATED_METADATA_NAME]
    }
}

fun mapOAuth2ClientCredentialsGrantAuthorization(
    clientCredentialsGrantAuthorization: RedisOAuth2ClientCredentialsGrantAuthorization, builder: Builder
) {
    builder.id(clientCredentialsGrantAuthorization.id).principalName(clientCredentialsGrantAuthorization.principalName)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .authorizedScopes(clientCredentialsGrantAuthorization.authorizedScopes)

    mapAccessToken(clientCredentialsGrantAuthorization.accessToken, builder)
}
