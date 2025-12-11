package com.example.opaque_demo.model

import com.example.opaque_demo.utils.Base64ByteArraySerializer
import kotlinx.serialization.Serializable
import java.time.Duration

@Serializable
data class RequestPayload(
    val protocol: String,
    val state: String,
    val task: String?,
    // there is also a session_duration: Duration that could optionally be sent.
    @Serializable(with = Base64ByteArraySerializer::class)
    val authorization: ByteArray?,
    @Serializable(with = Base64ByteArraySerializer::class)
    val req: ByteArray,
)

class RequestPayloadBuilder {
    private var protocol: String = "opaque"
    private var state: String = ""
    private var task: String? = null
    private var authorization: ByteArray? = null
    private var req: ByteArray? = null

    fun setState(state: String) = apply { this.state = state }
    fun setTask(task: String) = apply { this.task = task }
    fun setAuthorization(authorization: ByteArray?) = apply { this.authorization = authorization }
    fun setReq(req: ByteArray) = apply { this.req = req }

    fun build(): RequestPayload {
        require(state.isNotEmpty()) { "state must be set" }
        val requestData = req ?: throw IllegalStateException("req must be set")

        return RequestPayload(
            protocol = protocol,
            state = state,
            task = task,
            authorization = authorization,
            req = requestData
        )
    }
}
