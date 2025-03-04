package com.origincoding.authorization.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.core.io.ClassPathResource
import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@Component
@ConfigurationProperties(prefix = "security.rsa")
@OptIn(ExperimentalEncodingApi::class)
class RsaKeyPairConfig(
    var privateKeyPath: String = "",
    var publicKeyPath: String = ""
) {
    fun loadKeyPair(): KeyPair = KeyPair(loadPublicKey(), loadPrivateKey())

    private fun loadPrivateKey(): PrivateKey {
        val resource = ClassPathResource(privateKeyPath)
        val keyBytes = parsePEM(resource.inputStream.readAllBytes())
        return KeyFactory.getInstance("RSA")
            .generatePrivate(PKCS8EncodedKeySpec(keyBytes))
    }

    private fun loadPublicKey(): PublicKey {
        val resource = ClassPathResource(publicKeyPath)
        val keyBytes = parsePEM(resource.inputStream.readAllBytes())
        return KeyFactory.getInstance("RSA")
            .generatePublic(X509EncodedKeySpec(keyBytes))
    }

    private fun parsePEM(pemBytes: ByteArray): ByteArray {
        val pem = String(pemBytes)
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\n", "")
        return Base64.decode(pem)
    }
}