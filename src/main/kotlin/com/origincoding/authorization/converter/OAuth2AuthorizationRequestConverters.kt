package com.origincoding.authorization.converter

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.core.convert.converter.Converter
import org.springframework.data.convert.ReadingConverter
import org.springframework.data.convert.WritingConverter
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module


@WritingConverter
class OAuth2AuthorizationRequestToBytesConverter : Converter<OAuth2AuthorizationRequest, ByteArray> {
    private val serializer: Jackson2JsonRedisSerializer<OAuth2AuthorizationRequest>

    init {
        val objectMapper = jacksonObjectMapper()
        objectMapper.registerModules(
            SecurityJackson2Modules.getModules(OAuth2AuthorizationRequestToBytesConverter::class.java.classLoader)
        )
        objectMapper.registerModules(OAuth2AuthorizationServerJackson2Module())
        this.serializer = Jackson2JsonRedisSerializer(
            objectMapper, OAuth2AuthorizationRequest::class.java
        )
    }

    override fun convert(value: OAuth2AuthorizationRequest): ByteArray {
        return serializer.serialize(value)
    }
}

@ReadingConverter
class BytesToOAuth2AuthorizationRequestConverter : Converter<ByteArray, OAuth2AuthorizationRequest> {
    private val serializer: Jackson2JsonRedisSerializer<OAuth2AuthorizationRequest>

    init {
        val objectMapper = jacksonObjectMapper()
        objectMapper.registerModules(
            SecurityJackson2Modules.getModules(BytesToOAuth2AuthorizationRequestConverter::class.java.classLoader)
        )
        objectMapper.registerModule(OAuth2AuthorizationServerJackson2Module())
        this.serializer = Jackson2JsonRedisSerializer(
            objectMapper, OAuth2AuthorizationRequest::class.java
        )
    }

    override fun convert(value: ByteArray): OAuth2AuthorizationRequest {
        return serializer.deserialize(value)
    }
}
