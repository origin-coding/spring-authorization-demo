package com.origincoding.authorization.config

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.annotation.PropertyAccessor
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.origincoding.authorization.converter.*
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.RedisConnectionFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.core.convert.RedisCustomConversions
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer
import org.springframework.data.redis.serializer.StringRedisSerializer
import org.springframework.security.jackson2.SecurityJackson2Modules


@EnableRedisRepositories
@Configuration(proxyBeanMethods = false)
class RedisConfig {
    @Bean
    fun <T> redisTemplate(redisConnectionFactory: RedisConnectionFactory): RedisTemplate<String, T> {
        // 创建RedisTemplate
        val redisTemplate: RedisTemplate<String, T> = RedisTemplate()
        redisTemplate.connectionFactory = redisConnectionFactory

        // 设置Key的序列化类型
        val stringRedisSerializer = StringRedisSerializer()
        redisTemplate.keySerializer = stringRedisSerializer

        // 设置Value的序列化类型
        // 创建ObjectMapper
        val mapper = jacksonObjectMapper()
        // 注册相关的Modules
        mapper.registerModules(SecurityJackson2Modules.getModules(javaClass.classLoader))

        mapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY)
        mapper.activateDefaultTyping(
            LaissezFaireSubTypeValidator.instance,
            ObjectMapper.DefaultTyping.NON_FINAL,
            JsonTypeInfo.As.PROPERTY
        )

        // 创建JsonSerializer
        val jsonSerializer: Jackson2JsonRedisSerializer<Any> = Jackson2JsonRedisSerializer(mapper, Any::class.java)
        // 设置Value的序列化类型
        redisTemplate.valueSerializer = jsonSerializer

        // 设置Hash的Key-Value序列化类型
        redisTemplate.hashKeySerializer = stringRedisSerializer
        redisTemplate.hashValueSerializer = jsonSerializer

        // 初始化RedisTemplate
        redisTemplate.afterPropertiesSet()
        // 返回RedisTemplate
        return redisTemplate
    }

    @Bean
    fun bytesRedisTemplate(redisConnectionFactory: RedisConnectionFactory): RedisTemplate<ByteArray, ByteArray> {
        // 创建RedisTemplate
        val redisTemplate: RedisTemplate<ByteArray, ByteArray> = RedisTemplate()
        redisTemplate.connectionFactory = redisConnectionFactory
        return redisTemplate
    }

    @Bean
    fun redisCustomConversions(): RedisCustomConversions {
        return RedisCustomConversions(
            listOf(
                UsernamePasswordAuthenticationTokenToBytesConverter(),
                BytesToUsernamePasswordAuthenticationTokenConverter(),
                OAuth2AuthorizationRequestToBytesConverter(), BytesToOAuth2AuthorizationRequestConverter(),
                ClaimsHolderToBytesConverter(), BytesToClaimsHolderConverter()
            )
        )
    }
}
