package com.example.opaque_demo

import kotlinx.serialization.Serializable

@Serializable
data class WorkerResponse(
    val correlationId: String,
    val result: String? = null,
    val resultUrl: String? = null,
    val stateJws: String? = null,
    val status: String
)