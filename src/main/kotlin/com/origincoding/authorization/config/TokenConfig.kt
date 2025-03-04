package com.origincoding.authorization.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.token.*
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

@Configuration
class TokenConfig(
    val rsaKeyPairConfig: RsaKeyPairConfig
) {
    companion object {
        const val JWT_KEY_AUTHORITIES = "authorities"
    }

    // JwtTokenCustomizer用于在登录时将权限写入到Jwt中

    @Bean
    fun jwtTokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> = OAuth2TokenCustomizer { context ->
//        if (context.tokenType == OAuth2TokenType.ACCESS_TOKEN) {
//
//        }
        val authorities = AuthorityUtils.authorityListToSet(context.getPrincipal<Authentication>().authorities)
            .map { it.replaceFirst("^ROLE_", "") }.toSet()
        context.claims.claims { it[JWT_KEY_AUTHORITIES] = authorities }
    }

    @Bean
    fun jwtAuthenticationConverter(): JwtAuthenticationConverter {
        val grantedAuthoritiesConverter = JwtGrantedAuthoritiesConverter().apply {
            setAuthorityPrefix("")
            setAuthoritiesClaimName(JWT_KEY_AUTHORITIES)
        }
        return JwtAuthenticationConverter().apply { setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter) }
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair = rsaKeyPairConfig.loadKeyPair()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        val rsaKey: RSAKey =
            RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build()
        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet(jwkSet)
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

    @Bean
    fun tokenGenerator(jwkSource: JWKSource<SecurityContext?>?): OAuth2TokenGenerator<*> {
        val jwtGenerator = JwtGenerator(NimbusJwtEncoder(jwkSource))
        jwtGenerator.setJwtCustomizer(jwtTokenCustomizer())

        val accessTokenGenerator = OAuth2AccessTokenGenerator()
        val refreshTokenGenerator = OAuth2RefreshTokenGenerator()

        return DelegatingOAuth2TokenGenerator(
            accessTokenGenerator, refreshTokenGenerator, jwtGenerator
        )
    }
}