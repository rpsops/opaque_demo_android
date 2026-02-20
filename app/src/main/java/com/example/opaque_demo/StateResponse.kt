package com.example.opaque_demo

import kotlinx.serialization.Serializable

@Serializable
data class StateResponse(val status: String, val clientId: String, val devAuthorizationCode: String)