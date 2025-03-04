package com.origincoding.authorization.config

import com.origincoding.authorization.config.converter.PasswordGrantAuthorizationConverter
import com.origincoding.authorization.config.provider.PasswordGrantAuthenticationProvider
import com.origincoding.authorization.service.RedisOAuth2AuthorizationService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.*
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.util.*
import kotlin.uuid.ExperimentalUuidApi


@ExperimentalUuidApi
@Configuration
class AuthenticationConfig(
    private val tokenGenerator: OAuth2TokenGenerator<*>,
    private val authorizationService: RedisOAuth2AuthorizationService
) {
    @Bean
    @Order(1)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer()

        http.securityMatcher(authorizationServerConfigurer.endpointsMatcher)
            .with(authorizationServerConfigurer) { configurer ->
                configurer.oidc(Customizer.withDefaults())
                configurer.tokenEndpoint {
                    it.accessTokenRequestConverter(PasswordGrantAuthorizationConverter())
                    it.authenticationProvider(
                        PasswordGrantAuthenticationProvider(
                            userDetailsService(),
                            passwordEncoder(),
                            tokenGenerator,
                            authorizationService
                        )
                    )
                }
            }
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .exceptionHandling {
                it.defaultAuthenticationEntryPointFor(
                    LoginUrlAuthenticationEntryPoint("/login"),
                    MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            }

        return http.build()
    }

    @Bean
    @Order(2)
    @Throws(Exception::class)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain = http
        // 全部的请求都需要认证
        .authorizeHttpRequests { it.anyRequest().authenticated() }
        // 使用默认表单登录
        .formLogin(Customizer.withDefaults()).build()

    @Bean
    fun userDetailsService(): UserDetailsService {
        return InMemoryUserDetailsManager(
            User(
                "user",
                passwordEncoder().encode("password"),
                AuthorityUtils.createAuthorityList("ROLE_USER", "test_authority")
            )
        )
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder().build()
    }
}