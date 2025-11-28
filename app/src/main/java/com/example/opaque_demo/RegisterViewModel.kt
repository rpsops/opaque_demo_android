package com.example.opaque_demo

import android.util.Log
import androidx.lifecycle.ViewModel
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import se.digg.opaque_ke_uniffi.clientLoginFinish
import se.digg.opaque_ke_uniffi.clientLoginStart
import se.digg.opaque_ke_uniffi.clientRegistrationFinish
import se.digg.opaque_ke_uniffi.clientRegistrationStart
import se.digg.opaque_ke_uniffi.serverLoginFinish
import se.digg.opaque_ke_uniffi.serverLoginStart
import se.digg.opaque_ke_uniffi.serverRegistrationFinish
import se.digg.opaque_ke_uniffi.serverRegistrationStart
import se.digg.opaque_ke_uniffi.serverSetup
import java.time.Instant

class RegisterViewModel : ViewModel() {

    private val _result = MutableStateFlow<String?>(null)
    val result = _result.asStateFlow()

    fun register() {
        val clientRegStartResult = clientRegistrationStart(byteArrayOf(1, 2, 3))

        val serverSetup = serverSetup();
        val serverRegStartResult =
            serverRegistrationStart(
                serverSetup,
                clientRegStartResult.registrationRequest,
                byteArrayOf(1, 2)
            )

        val clientRegFinishResult = clientRegistrationFinish(
            byteArrayOf(1, 2, 3),
            clientRegStartResult.clientRegistration,
            serverRegStartResult
        )

        val passwordFile =
            serverRegistrationFinish(clientRegFinishResult.registrationUpload)

        val startTime = System.currentTimeMillis()

        val clientLoginStart = clientLoginStart(byteArrayOf(1, 2, 3))

        val endClient1 = System.currentTimeMillis()
        val serverLoginStart = serverLoginStart(
            serverSetup,
            passwordFile,
            clientLoginStart.credentialRequest,
            byteArrayOf(1, 2)
        )

        val startClient = System.currentTimeMillis()
        val clientLoginFinish = clientLoginFinish(
            serverLoginStart.credentialResponse,
            clientLoginStart.clientRegistration,
            byteArrayOf(1, 2, 3)
        )
        val endClient2 = System.currentTimeMillis()

        val clientSessionKey = clientLoginFinish.sessionKey

        val serverLoginFinish = serverLoginFinish(
            serverLoginStart.serverLogin,
            clientLoginFinish.credentialFinalization
        )

        val serverSessionKey = serverLoginFinish

        val endTime = System.currentTimeMillis()
        Log.d("OpaqueDemo", "Opaque process took ${endTime - startTime} ms")
        Log.d(
            "OpaqueDemo",
            "Client took ${(endClient1 - startTime) + (endClient2 - startClient)} ms"
        )
        _result.value =
            "Opaque process took ${endTime - startTime} ms\n Client took ${(endClient1 - startTime) + (endClient2 - startClient)} ms"
    }

    fun testJWS() {
        val clientRegStartResult = clientRegistrationStart(byteArrayOf(1, 2, 3))

        // this is the blind that we'll save for later
        val clientRegistration = clientRegStartResult.clientRegistration

        // result to send to server
        val registrationRequest = clientRegStartResult.registrationRequest

        // create the payload
        val payload = Payload("opaque", "evaluate", null, registrationRequest)

        // encrypt the payload
        // todo make this happen
        val encryptedPayload = byteArrayOf(/*payload*/)


        // wrap the payload
        val payloadWrapper = PayloadWrapper(
            "https://wallets/digg.se/1234567890",
            "wallet-hsm-key-1",
            "hsm",
            "pin_registration",
            null,
            "1.0",
            "1234567890",
            Instant.now(),
            "device",
            encryptedPayload
        )

        // create JWS headers
        // todo hard coded
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JOSE).build()

        // create JWSObject
        // todo check serialization
        val jwsObject = JWSObject(
            header,
            com.nimbusds.jose.Payload(Json.encodeToString(payloadWrapper))
        )

        // sign JWS
        // todo figure out signer params
        jwsObject.sign()




    }


    // we're probably not going to use context
    @Serializable
    private data class PayloadWrapper(
        val client_id: String,
        val kid: String,
        val context: String,
        val type: String,
        val pake_session_id: String?,
        val ver: String,
        val nonce: String,
        val iat: Instant,
        val enc: String,
        val data: ByteArray
    )

    private data class Payload(
        val protocol: String,
        val state: String,
        val authorization: ByteArray?,
        val req: ByteArray
    )


}
