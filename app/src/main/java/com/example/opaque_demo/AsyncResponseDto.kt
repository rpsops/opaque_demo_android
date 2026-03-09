package com.example.opaque_demo

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonIgnoreUnknownKeys

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonIgnoreUnknownKeys
data class AsyncResponseDto(
    val correlationId: String,
    val status: AsyncResponseStatus,
    val result: String? = null,
    val resultUrl: String? = null,
    val error: AsyncResponseError? = null
)

@Serializable
enum class AsyncResponseStatus {
    PENDING,
    COMPLETE,
    ERROR
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonIgnoreUnknownKeys
data class AsyncResponseError(
    val message: String,
    val httpStatus: Int
)
