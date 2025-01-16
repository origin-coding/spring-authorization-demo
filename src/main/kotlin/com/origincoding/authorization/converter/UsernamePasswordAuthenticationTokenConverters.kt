package com.origincoding.authorization.converter

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.core.convert.converter.Converter
import org.springframework.data.convert.ReadingConverter
import org.springframework.data.convert.WritingConverter
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.jackson2.SecurityJackson2Modules


@ReadingConverter
class BytesToUsernamePasswordAuthenticationTokenConverter : Converter<ByteArray, UsernamePasswordAuthenticationToken> {
    private val serializer: Jackson2JsonRedisSerializer<UsernamePasswordAuthenticationToken>

    init {
        val objectMapper = jacksonObjectMapper()
        objectMapper.registerModules(
            SecurityJackson2Modules.getModules(BytesToUsernamePasswordAuthenticationTokenConverter::class.java.classLoader)
        )
        this.serializer = Jackson2JsonRedisSerializer(
            objectMapper, UsernamePasswordAuthenticationToken::class.java
        )
    }

    override fun convert(value: ByteArray): UsernamePasswordAuthenticationToken {
        return serializer.deserialize(value)
    }
}

@WritingConverter
class UsernamePasswordAuthenticationTokenToBytesConverter : Converter<UsernamePasswordAuthenticationToken, ByteArray> {
    private val serializer: Jackson2JsonRedisSerializer<UsernamePasswordAuthenticationToken>

    init {
        val objectMapper = jacksonObjectMapper()
        objectMapper.registerModules(
            SecurityJackson2Modules.getModules(UsernamePasswordAuthenticationTokenToBytesConverter::class.java.classLoader)
        )
        this.serializer = Jackson2JsonRedisSerializer(
            objectMapper, UsernamePasswordAuthenticationToken::class.java
        )
    }

    override fun convert(value: UsernamePasswordAuthenticationToken): ByteArray {
        return serializer.serialize(value)
    }
}
