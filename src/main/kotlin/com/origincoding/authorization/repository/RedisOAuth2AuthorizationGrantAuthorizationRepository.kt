package com.origincoding.authorization.repository

import com.origincoding.authorization.domain.dto.RedisOAuth2AuthorizationCodeGrantAuthorization
import com.origincoding.authorization.domain.dto.RedisOAuth2AuthorizationGrantAuthorization
import com.origincoding.authorization.domain.dto.RedisOidcAuthorizationCodeGrantAuthorization
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository

@Suppress("SpringDataMethodInconsistencyInspection", "FunctionName")
@Repository
interface RedisOAuth2AuthorizationGrantAuthorizationRepository :
    CrudRepository<RedisOAuth2AuthorizationGrantAuthorization, String> {

    fun <T : RedisOAuth2AuthorizationCodeGrantAuthorization> findByState(state: String): T?

    fun <T : RedisOAuth2AuthorizationCodeGrantAuthorization> findByAuthorizationCode_TokenValue(authorizationCode: String): T?

    fun <T : RedisOAuth2AuthorizationCodeGrantAuthorization> findByStateOrAuthorizationCode_TokenValue(
        string: String,
        authorizationCode: String
    ): T?

    fun <T : RedisOAuth2AuthorizationGrantAuthorization> findByAccessToken_TokenValue(accessToken: String): T?

    fun <T : RedisOAuth2AuthorizationGrantAuthorization> findByRefreshToken_TokenValue(refreshToken: String): T?

    fun <T : RedisOAuth2AuthorizationGrantAuthorization> findByAccessToken_TokenValueOrRefreshToken_TokenValue(
        accessToken: String,
        refreshToken: String
    ): T?

    fun <T : RedisOidcAuthorizationCodeGrantAuthorization> findByIdToken_TokenValue(idToken: String): T?
}