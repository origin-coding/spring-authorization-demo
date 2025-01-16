package com.origincoding.authorization.repository

import com.origincoding.authorization.domain.dto.RedisRegisteredClient
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository

@Repository
interface RedisRegisteredClientRepository : CrudRepository<RedisRegisteredClient, String> {
    fun findByClientId(clientId: String): RedisRegisteredClient?
}