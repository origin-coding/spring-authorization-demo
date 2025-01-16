package com.origincoding.authorization.converter

import com.fasterxml.jackson.annotation.*
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.origincoding.authorization.domain.dto.RedisOAuth2AuthorizationGrantAuthorization
import org.springframework.core.convert.converter.Converter
import org.springframework.data.convert.ReadingConverter
import org.springframework.data.convert.WritingConverter
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module


@Suppress("UNUSED_PARAMETER")
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(
    fieldVisibility = JsonAutoDetect.Visibility.ANY,
    getterVisibility = JsonAutoDetect.Visibility.NONE,
    isGetterVisibility = JsonAutoDetect.Visibility.NONE,
    creatorVisibility = JsonAutoDetect.Visibility.NONE
)
@JsonIgnoreProperties(ignoreUnknown = true)
internal abstract class ClaimsHolderMixin @JsonCreator constructor(@JsonProperty("claims") claims: Map<String, Any>?)

@WritingConverter
class ClaimsHolderToBytesConverter : Converter<RedisOAuth2AuthorizationGrantAuthorization.ClaimsHolder, ByteArray> {
    private val serializer: Jackson2JsonRedisSerializer<RedisOAuth2AuthorizationGrantAuthorization.ClaimsHolder>

    init {
        val objectMapper = jacksonObjectMapper()
        objectMapper.registerModules(SecurityJackson2Modules.getModules(ClaimsHolderToBytesConverter::class.java.classLoader))
        objectMapper.registerModules(OAuth2AuthorizationServerJackson2Module())
        objectMapper.addMixIn(
            RedisOAuth2AuthorizationGrantAuthorization.ClaimsHolder::class.java, ClaimsHolderMixin::class.java
        )
        this.serializer = Jackson2JsonRedisSerializer(
            objectMapper, RedisOAuth2AuthorizationGrantAuthorization.ClaimsHolder::class.java
        )
    }

    override fun convert(value: RedisOAuth2AuthorizationGrantAuthorization.ClaimsHolder): ByteArray {
        return serializer.serialize(value)
    }
}

@ReadingConverter
class BytesToClaimsHolderConverter : Converter<ByteArray, RedisOAuth2AuthorizationGrantAuthorization.ClaimsHolder> {
    private val serializer: Jackson2JsonRedisSerializer<RedisOAuth2AuthorizationGrantAuthorization.ClaimsHolder>

    init {
        val objectMapper = ObjectMapper()
        objectMapper.registerModules(SecurityJackson2Modules.getModules(BytesToClaimsHolderConverter::class.java.classLoader))
        objectMapper.registerModule(OAuth2AuthorizationServerJackson2Module())
        objectMapper.addMixIn(
            RedisOAuth2AuthorizationGrantAuthorization.ClaimsHolder::class.java, ClaimsHolderMixin::class.java
        )
        this.serializer = Jackson2JsonRedisSerializer(
            objectMapper, RedisOAuth2AuthorizationGrantAuthorization.ClaimsHolder::class.java
        )
    }

    override fun convert(value: ByteArray): RedisOAuth2AuthorizationGrantAuthorization.ClaimsHolder {
        return serializer.deserialize(value)
    }
}
