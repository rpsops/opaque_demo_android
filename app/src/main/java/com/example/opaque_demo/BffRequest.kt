package com.example.opaque_demo

import kotlinx.serialization.Serializable

@Serializable
data class BffRequest(val clientId: String, val outerRequestJws: String) {

}