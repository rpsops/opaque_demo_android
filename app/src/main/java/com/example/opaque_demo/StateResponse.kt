package com.example.opaque_demo

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.Serializable

@Serializable
data class StateResponse(
    val status: String,
    val clientId: String,
    val devAuthorizationCode: String,
    @Serializable(with = JwkSerializer::class) val serverJwsPublicKey: JWK?,
    val opaqueServerId: String,
)