package com.origincoding.authorization.converter

import com.fasterxml.jackson.annotation.*
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.origincoding.authorization.domain.dto.token.ClaimsHolder
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
class ClaimsHolderToBytesConverter : Converter<ClaimsHolder, ByteArray> {
    private val serializer: Jackson2JsonRedisSerializer<ClaimsHolder>

    init {
        val objectMapper = jacksonObjectMapper()
        objectMapper.registerModules(SecurityJackson2Modules.getModules(ClaimsHolderToBytesConverter::class.java.classLoader))
        objectMapper.registerModules(OAuth2AuthorizationServerJackson2Module())
        objectMapper.addMixIn(
            ClaimsHolder::class.java, ClaimsHolderMixin::class.java
        )
        this.serializer = Jackson2JsonRedisSerializer(
            objectMapper, ClaimsHolder::class.java
        )
    }

    override fun convert(value: ClaimsHolder): ByteArray {
        return serializer.serialize(value)
    }
}

@ReadingConverter
class BytesToClaimsHolderConverter : Converter<ByteArray, ClaimsHolder> {
    private val serializer: Jackson2JsonRedisSerializer<ClaimsHolder>

    init {
        val objectMapper = ObjectMapper()
        objectMapper.registerModules(SecurityJackson2Modules.getModules(BytesToClaimsHolderConverter::class.java.classLoader))
        objectMapper.registerModule(OAuth2AuthorizationServerJackson2Module())
        objectMapper.addMixIn(
            ClaimsHolder::class.java, ClaimsHolderMixin::class.java
        )
        this.serializer = Jackson2JsonRedisSerializer(
            objectMapper, ClaimsHolder::class.java
        )
    }

    override fun convert(value: ByteArray): ClaimsHolder {
        return serializer.deserialize(value)
    }
}
