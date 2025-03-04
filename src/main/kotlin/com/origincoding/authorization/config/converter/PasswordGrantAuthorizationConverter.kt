package com.origincoding.authorization.config.converter

import com.origincoding.authorization.domain.dto.token.PasswordGrantAuthenticationToken
import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.util.StringUtils

class PasswordGrantAuthorizationConverter : AuthenticationConverter {
    override fun convert(request: HttpServletRequest): Authentication? {
        val grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE)
        if (OAuth2ParameterNames.PASSWORD != grantType) {
            return null
        }

        val clientPrincipal = SecurityContextHolder.getContext().authentication
        val parameters = getParameters(request)

        val username = parameters.getFirst(OAuth2ParameterNames.USERNAME)
        if (!StringUtils.hasText(username) || parameters[OAuth2ParameterNames.USERNAME]?.size != 1) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        val password = parameters.getFirst(OAuth2ParameterNames.PASSWORD)
        if (!StringUtils.hasText(password) || parameters[OAuth2ParameterNames.PASSWORD]?.size != 1) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        // get value[0] from parameters
        val additionalParameters = parameters.filter {
            it.key !in listOf(
                OAuth2ParameterNames.GRANT_TYPE,
                OAuth2ParameterNames.CLIENT_ID,
                OAuth2ParameterNames.CODE
            )
        }.mapValues { it.value[0] }

        return PasswordGrantAuthenticationToken(clientPrincipal, additionalParameters)
    }

    private fun getParameters(request: HttpServletRequest): MultiValueMap<String, String> {
        return request.parameterMap.filter { it.value.isNotEmpty() }
            .mapValues { it.value.toList() }
            .let { LinkedMultiValueMap(it) }
    }
}