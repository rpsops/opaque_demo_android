package com.example.opaque_demo

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject

@Serializable
data class StateRequest(
    @Serializable(with = JwkSerializer::class) val publicKey: JWK,
    val clientId: String,
    val overwrite: Boolean = false,
    val ttl: String
)

internal object JwkSerializer : KSerializer<JWK> {
    override val descriptor: SerialDescriptor = JsonObject.serializer().descriptor

    override fun serialize(encoder: Encoder, value: JWK) {
        val jsonEncoder = encoder as? JsonEncoder
            ?: throw IllegalStateException("This serializer can be used only with Json format")
        val element = Json.parseToJsonElement(value.toJSONString())
        jsonEncoder.encodeJsonElement(element)
    }

    override fun deserialize(decoder: Decoder): JWK {
        val jsonDecoder = decoder as? JsonDecoder
            ?: throw IllegalStateException("This serializer can be used only with Json format")
        val element = jsonDecoder.decodeJsonElement()
        return JWK.parse(element.toString())
    }
}