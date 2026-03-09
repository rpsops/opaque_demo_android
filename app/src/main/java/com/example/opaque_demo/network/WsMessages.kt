package com.example.opaque_demo.network

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonIgnoreUnknownKeys
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

// ─── JSON Configuration ───

/**
 * Json instance configured for the WebSocket protocol.
 * Uses "type" as the class discriminator to match the server's
 * serde(tag = "type", rename_all = "snake_case") format.
 */
@OptIn(ExperimentalSerializationApi::class)
val wsJson = Json {
    classDiscriminator = "type"
    ignoreUnknownKeys = true
    encodeDefaults = false
    serializersModule = SerializersModule {
        polymorphic(WsClientMessage::class) {
            subclass(WsAuthInit::class)
            subclass(WsAuthResponse::class)
            subclass(WsRequest::class)
        }
        polymorphic(WsServerMessage::class) {
            subclass(WsAuthChallenge::class)
            subclass(WsAuthOk::class)
            subclass(WsAuthError::class)
            subclass(WsResponse::class)
            subclass(WsRequestError::class)
            subclass(WsError::class)
        }
    }
}

// ─── Client-to-Server Messages ───

@Serializable
sealed class WsClientMessage

@Serializable
@SerialName("auth_init")
data class WsAuthInit(
    val clientId: String
) : WsClientMessage()

@Serializable
@SerialName("auth_response")
data class WsAuthResponse(
    val enc: String,
    val ciphertext: String
) : WsClientMessage()

@Serializable
@SerialName("request")
data class WsRequest(
    val requestId: String,
    val outerRequestJws: String
) : WsClientMessage()

// ─── Server-to-Client Messages ───

@Serializable
sealed class WsServerMessage

@Serializable
@SerialName("auth_challenge")
data class WsAuthChallenge(
    val enc: String,
    val ciphertext: String,
    val salt: String,
    val serverKid: String
) : WsServerMessage()

@Serializable
@SerialName("auth_ok")
data class WsAuthOk(
    val clientId: String
) : WsServerMessage()

@Serializable
@SerialName("auth_error")
data class WsAuthError(
    val message: String
) : WsServerMessage()

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@SerialName("response")
@JsonIgnoreUnknownKeys
data class WsResponse(
    val requestId: String? = null,
    val correlationId: String,
    val status: String,
    val result: String? = null,
    val error: WsResponseError? = null
) : WsServerMessage()

@Serializable
@SerialName("request_error")
data class WsRequestError(
    val requestId: String,
    val message: String
) : WsServerMessage()

@Serializable
@SerialName("error")
data class WsError(
    val message: String
) : WsServerMessage()

@Serializable
data class WsResponseError(
    val message: String,
    val httpStatus: Int
)
