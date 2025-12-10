package com.example.opaque_demo.model

import com.example.opaque_demo.utils.Base64ByteArraySerializer
import com.example.opaque_demo.utils.InstantEpochSecondsSerializer
import kotlinx.serialization.Serializable
import java.time.Instant

@Serializable
data class PayloadWrapper(
    val client_id: String,
    val kid: String,
    val context: String,
    val type: String,
    val pake_session_id: String?,
    val ver: String,
    val nonce: String,
    @Serializable(with = InstantEpochSecondsSerializer::class)
    val iat: Instant,
    val enc: String,
    @Serializable(with = Base64ByteArraySerializer::class)
    val data: ByteArray
)

@Serializable
data class ServerPayloadWrapper(
    val ver: String,
    val nonce: String,
    @Serializable(with = InstantEpochSecondsSerializer::class)
    val iat: Instant,
    val enc: String,
    @Serializable(with = Base64ByteArraySerializer::class)
    val data: ByteArray
)

@Serializable
data class ServerResponsePayload(
    @Serializable(with = Base64ByteArraySerializer::class)
    val resp: ByteArray? = null,
    val msg: String? = null,
    val pake_session_id: String? = null
)
