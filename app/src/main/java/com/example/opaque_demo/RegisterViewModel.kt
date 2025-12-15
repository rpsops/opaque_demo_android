package com.example.opaque_demo

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.opaque_demo.model.OpaqueOperationState
import com.example.opaque_demo.model.OpaqueOperationType
import com.example.opaque_demo.model.RequestPayloadBuilder
import com.example.opaque_demo.model.ServerPayloadWrapper
import com.example.opaque_demo.model.ServerResponsePayload
import com.example.opaque_demo.network.OpaqueService
import com.example.opaque_demo.security.OpaqueCryptoManager
import com.example.opaque_demo.utils.toHexString
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import se.digg.opaque_ke_uniffi.ClientLoginFinishResult
import se.digg.opaque_ke_uniffi.clientLoginFinish
import se.digg.opaque_ke_uniffi.clientLoginStart
import se.digg.opaque_ke_uniffi.clientRegistrationFinish
import se.digg.opaque_ke_uniffi.clientRegistrationStart
import se.digg.opaque_ke_uniffi.serverLoginFinish
import se.digg.opaque_ke_uniffi.serverLoginStart
import se.digg.opaque_ke_uniffi.serverRegistrationFinish
import se.digg.opaque_ke_uniffi.serverRegistrationStart
import se.digg.opaque_ke_uniffi.serverSetup
import java.security.SecureRandom
import java.time.Instant

class RegisterViewModel : ViewModel() {

    private val service = OpaqueService()

    val clientIdentifier = "https://wallets/digg.se/1234567890".toByteArray()
    val serverIdentifier = "https://cloud-wallet.digg.se/rhsm".toByteArray()
    val opaqueContext = "RPS-Ops".toByteArray()

    private val _result = MutableStateFlow<String?>(null)
    val result = _result.asStateFlow()

    val authorizationCode: ByteArray = ByteArray(16)


    /**
     * Register the authentication code for the device
     * This should already be available on the server. This is just to be able to run a registerPin
     */
    fun registerAuthentication(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val cryptoManager = OpaqueCryptoManager(context, String(clientIdentifier))

            SecureRandom().nextBytes(authorizationCode)
            val encryptedPayload = cryptoManager.encryptBytes(authorizationCode)

            val nonce = cryptoManager.generateNonce()

            val signedJws =
                cryptoManager.createSignedJws(
                    OpaqueOperationType.REGISTER_AUTHORIZATION.type,
                    nonce,
                    encryptedPayload,
                    null
                )

            val registerResponse = service.sendRequest(signedJws.serialize())
            // We don't care about the result. This is just for testing
        }
    }

    /**
     * Register a pin (123) for the device
     */
    fun registerPin(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val cryptoManager = OpaqueCryptoManager(context, String(clientIdentifier))

            val hardPin = cryptoManager.stretchPin(byteArrayOf(1, 2, 3))

            // Client start
            val clientRegStartResult = clientRegistrationStart(hardPin)

            val registrationResponse = executeOpaqueRequest(
                cryptoManager,
                OpaqueOperationType.PIN_REGISTRATION.type,
                OpaqueOperationState.EVALUATE.state,
                clientRegStartResult.registrationRequest,
            )

            // Client finish
            val clientRegFinishResult = clientRegistrationFinish(
                hardPin,
                clientRegStartResult.clientRegistration,
                registrationResponse.resp!!,
                clientIdentifier,
                serverIdentifier
            )

            val serverFinalizePayload = executeOpaqueRequest(
                cryptoManager,
                OpaqueOperationType.PIN_REGISTRATION.type,
                OpaqueOperationState.FINALIZE.state,
                clientRegFinishResult.registrationUpload
            ) {
                setAuthorization(authorizationCode)
            }

            _result.value = "Register pin is: ${serverFinalizePayload.msg!!}"
        }
    }

    fun createSession(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val cryptoManager = OpaqueCryptoManager(context, String(clientIdentifier))

            val hardPin = cryptoManager.stretchPin(byteArrayOf(1, 2, 3))

            // client start
            val clientLoginStart = clientLoginStart(hardPin)

            val loginEvaluateResponse = executeOpaqueRequest(
                cryptoManager,
                OpaqueOperationType.AUTHENTICATE.type,
                OpaqueOperationState.EVALUATE.state,
                clientLoginStart.credentialRequest
            )

            // client finish
            lateinit var clientLoginFinish: ClientLoginFinishResult
            try {
                clientLoginFinish = clientLoginFinish(
                    loginEvaluateResponse.resp!!,
                    clientLoginStart.clientRegistration,
                    hardPin,
                    opaqueContext,
                    clientIdentifier,
                    serverIdentifier
                )
            } catch (e: Exception) {
                Log.e("OpaqueDemo", "Error creating session", e)
                return@launch
            }

            val serverFinalizePayload = executeOpaqueRequest(
                cryptoManager,
                OpaqueOperationType.AUTHENTICATE.type,
                OpaqueOperationState.FINALIZE.state,
                clientLoginFinish.credentialFinalization,
                loginEvaluateResponse.pake_session_id
            )
            { setTask("general") }

            _result.value =
                "Session key: \n${clientLoginFinish.sessionKey.toHexString()}"

            Log.d("OpaqueDemo", "Session key: ${clientLoginFinish.sessionKey.contentToString()}")
        }
    }

    private suspend fun executeOpaqueRequest(
        cryptoManager: OpaqueCryptoManager,
        type: String,
        state: String,
        requestBytes: ByteArray,
        pakeSessionId: String? = null,
        payloadConfig: (RequestPayloadBuilder.() -> Unit)? = null
    ): ServerResponsePayload {
        // create the payload
        val builder = RequestPayloadBuilder()
            .setState(state)
            .setReq(requestBytes)

        payloadConfig?.invoke(builder)

        val payload = builder.build()

        // encrypt the payload
        val encryptedPayload = cryptoManager.encryptPayload(payload)
        val nonce = cryptoManager.generateNonce()

        // sign the payload
        val signedJws = cryptoManager.createSignedJws(type, nonce, encryptedPayload, pakeSessionId)

        // send
        val response = service.sendRequest(signedJws.serialize())

        // handle response
        val wrapper = cryptoManager.extractPayloadWrapper(response)
        verifyWrapper(wrapper, nonce)
        return cryptoManager.decryptServerPayload(wrapper)
    }

    fun verifyWrapper(wrapper: ServerPayloadWrapper, nonce: String) {
        check(wrapper.data.isNotEmpty()) { "No data in response" }
        check(wrapper.nonce == nonce) { "Nonce mismatch" }
        // iat must not be more that 10s old and not more than 30s in the future
        check(
            wrapper.iat.isAfter(Instant.now().minusSeconds(10)) &&
                    wrapper.iat.isBefore(Instant.now().plusSeconds(30))
        ) { "Timestamp outside valid window" }
    }

    /**
     * Run the opaque process locally, without calling any server
     */
    fun localRegister(context: Context) {
        val cryptoManager = OpaqueCryptoManager(context, String(clientIdentifier))

        val hardPin = cryptoManager.stretchPin(byteArrayOf(1, 2, 3))

        val serverSetup = serverSetup()

        // registration
        val clientRegStartResult = clientRegistrationStart(hardPin)

        val serverRegStartResult =
            serverRegistrationStart(
                serverSetup,
                clientRegStartResult.registrationRequest,
                clientIdentifier
            )

        val clientRegFinishResult = clientRegistrationFinish(
            hardPin,
            clientRegStartResult.clientRegistration,
            serverRegStartResult,
            clientIdentifier,
            serverIdentifier
        )

        val passwordFile =
            serverRegistrationFinish(clientRegFinishResult.registrationUpload)


        // login/Create session
        val clientLoginStart = clientLoginStart(hardPin)

        val serverLoginStart = serverLoginStart(
            serverSetup,
            passwordFile,
            clientLoginStart.credentialRequest,
            clientIdentifier,
            opaqueContext,
            clientIdentifier,
            serverIdentifier
        )

        val clientLoginFinish = clientLoginFinish(
            serverLoginStart.credentialResponse,
            clientLoginStart.clientRegistration,
            hardPin,
            opaqueContext,
            clientIdentifier,
            serverIdentifier
        )

        val serverLoginFinish = serverLoginFinish(
            serverLoginStart.serverLogin,
            clientLoginFinish.credentialFinalization,
            opaqueContext,
            clientIdentifier,
            serverIdentifier,
        )

        // server and client has (hopefully) agreed on a session key
        if (serverLoginFinish.contentEquals(clientLoginFinish.sessionKey)) {
            _result.value = "In a local test the server and client agreed on session key: ${
                serverLoginFinish.toHexString()
            }"
        } else {
            Log.e(
                "OpaqueDemo",
                "Session key mismatch! Server and client could not agree on a session key."
            )
            _result.value = "Error: Session key mismatch!"
        }
    }
}
