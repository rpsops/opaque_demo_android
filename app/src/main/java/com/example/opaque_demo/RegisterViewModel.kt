package com.example.opaque_demo

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.opaque_demo.model.OpaqueOperationState
import com.example.opaque_demo.model.OpaqueOperationType
import com.example.opaque_demo.model.RequestPayloadBuilder
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

class RegisterViewModel : ViewModel() {

    private val service = OpaqueService()

    private val _result = MutableStateFlow<String?>(null)
    val result = _result.asStateFlow()

    val authenticationCode: ByteArray = ByteArray(16)


    /**
     * Register the authentication code for the device
     * This should already be available on the server. This is just to be able to run a registerPin
     */
    fun registerAuthentication(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val cryptoManager = OpaqueCryptoManager(context)

            SecureRandom().nextBytes(authenticationCode)
            val encryptedPayload = cryptoManager.encryptBytes(authenticationCode)

            val nonce = cryptoManager.generateNonce()

            val signedJws =
                cryptoManager.createSignedJws(
                    OpaqueOperationType.REGISTER_AUTHORIZATION.type,
                    nonce,
                    encryptedPayload
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
            val cryptoManager = OpaqueCryptoManager(context)

            // Client start
            val clientRegStartResult = clientRegistrationStart(byteArrayOf(1, 2, 3))

            // create the payload
            val evaluatePayload = RequestPayloadBuilder()
                .setState(OpaqueOperationState.EVALUATE.state)
                .setReq(clientRegStartResult.registrationRequest)
                .build()

            // encrypt the payload
            val encryptedPayload = cryptoManager.encryptPayload(evaluatePayload)

            val evalNonce = cryptoManager.generateNonce()

            // sign the payload
            val signedJws =
                cryptoManager.createSignedJws(
                    OpaqueOperationType.PIN_REGISTRATION.type,
                    evalNonce,
                    encryptedPayload
                )

            // send evaluate to server
            val serverEvaluateResponse = service.sendRequest(signedJws.serialize())

            // handle server evaluate response
            val serverPayloadWrapper = cryptoManager.extractPayloadWrapper(serverEvaluateResponse)

            val registrationResponse = cryptoManager.decryptServerPayload(serverPayloadWrapper)

            // Client finish
            val clientRegFinishResult = clientRegistrationFinish(
                byteArrayOf(1, 2, 3),
                clientRegStartResult.clientRegistration,
                registrationResponse.resp!!,
                "https://wallets/digg.se/1234567890".toByteArray(),
                "https://cloud-wallet.digg.se/rhsm".toByteArray()
            )

            // create the payload
            val finalizePayload = RequestPayloadBuilder()
                .setState(OpaqueOperationState.FINALIZE.state)
                .setAuthorization(authenticationCode)
                .setReq(clientRegFinishResult.registrationUpload)
                .build()

            val finalizeNonce = cryptoManager.generateNonce()

            // wrap and sign the payload
            val finalizeEncryptedPayload = cryptoManager.encryptPayload(finalizePayload)
            val signedFinalizeJws = cryptoManager.createSignedJws(
                OpaqueOperationType.PIN_REGISTRATION.type,
                finalizeNonce,
                finalizeEncryptedPayload
            )

            // send finalize to server
            val serverFinalizeResponse = service.sendRequest(signedFinalizeJws.serialize())

            // handle server finalize response
            val serverFinalizePayloadWrapper =
                cryptoManager.extractPayloadWrapper(serverFinalizeResponse)

            val serverFinalizePayload =
                cryptoManager.decryptServerPayload(serverFinalizePayloadWrapper)

            _result.value = "Register pin is: ${serverFinalizePayload.msg!!}"
        }
    }

    fun createSession(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val cryptoManager = OpaqueCryptoManager(context)

            // client start
            val clientLoginStart = clientLoginStart(byteArrayOf(1, 2, 3))

            // create the payload
            val evaluatePayload = RequestPayloadBuilder()
                .setState(OpaqueOperationState.EVALUATE.state)
                .setReq(clientLoginStart.credentialRequest)
                .build()

            // encrypt the payload
            val encryptedPayload = cryptoManager.encryptPayload(evaluatePayload)

            val evalNonce = cryptoManager.generateNonce()

            // sign the payload
            val signedJws =
                cryptoManager.createSignedJws(
                    OpaqueOperationType.AUTHENTICATE.type,
                    evalNonce,
                    encryptedPayload
                )

            // send evaluate to server
            val serverEvaluateResponse = service.sendRequest(signedJws.serialize())

            // handle server evaluate response
            val serverPayloadWrapper = cryptoManager.extractPayloadWrapper(serverEvaluateResponse)

            val loginEvaluateResponse = cryptoManager.decryptServerPayload(serverPayloadWrapper)

            lateinit var clientLoginFinish: ClientLoginFinishResult
            // client finish
            try {
                clientLoginFinish = clientLoginFinish(
                    loginEvaluateResponse.resp!!,
                    clientLoginStart.clientRegistration,
                    byteArrayOf(1, 2, 3),
                    "RPS-Ops".toByteArray(),
                    "https://wallets/digg.se/1234567890".toByteArray(),
                    "https://cloud-wallet.digg.se/rhsm".toByteArray()
                )
            } catch (e: Exception) {
                Log.e("OpaqueDemo", "Error creating session", e)
                return@launch
            }

            // create finalize payload
            val finalizePayload = RequestPayloadBuilder()
                .setState(OpaqueOperationState.FINALIZE.state)
                .setTask("general")
                .setReq(clientLoginFinish.credentialFinalization)
                .build()


            val finalizeNonce = cryptoManager.generateNonce()

            val finalizeEncryptedPayload = cryptoManager.encryptPayload(finalizePayload)

            // wrap and sign
            val signedFinalizeJws = cryptoManager.createSignedJws(
                OpaqueOperationType.AUTHENTICATE.type,
                finalizeNonce,
                finalizeEncryptedPayload,
                loginEvaluateResponse.pake_session_id
            )

            // send finalize
            val serverFinalizeResponse = service.sendRequest(signedFinalizeJws.serialize())

            // handle finalize response
            val serverFinalizePayloadWrapper =
                cryptoManager.extractPayloadWrapper(serverFinalizeResponse)

            val serverFinalizePayload =
                cryptoManager.decryptServerPayload(serverFinalizePayloadWrapper)

            Log.d("OpaqueDemo", "Session created: ${serverFinalizePayload.msg!!}")

            _result.value =
                "Session key: \n${clientLoginFinish.sessionKey.toHexString()}"

            Log.d("OpaqueDemo", "Session key: ${clientLoginFinish.sessionKey.contentToString()}")
        }
    }

    /**
     * Run the opaque process locally, without calling any server
     */
    fun localRegister() {
        val clientId = "clientId".toByteArray()
        val serverId = "serverId".toByteArray()
        val context = "context".toByteArray()

        val serverSetup = serverSetup()

        // registration
        val clientRegStartResult = clientRegistrationStart(byteArrayOf(1, 2, 3))

        val serverRegStartResult =
            serverRegistrationStart(
                serverSetup,
                clientRegStartResult.registrationRequest,
                clientId
            )

        val clientRegFinishResult = clientRegistrationFinish(
            byteArrayOf(1, 2, 3),
            clientRegStartResult.clientRegistration,
            serverRegStartResult,
            clientId,
            serverId
        )

        val passwordFile =
            serverRegistrationFinish(clientRegFinishResult.registrationUpload)


        // login/Create session
        val clientLoginStart = clientLoginStart(byteArrayOf(1, 2, 3))

        val serverLoginStart = serverLoginStart(
            serverSetup,
            passwordFile,
            clientLoginStart.credentialRequest,
            clientId,
            context,
            clientId,
            serverId
        )

        val clientLoginFinish = clientLoginFinish(
            serverLoginStart.credentialResponse,
            clientLoginStart.clientRegistration,
            byteArrayOf(1, 2, 3),
            context,
            clientId,
            serverId
        )

        val serverLoginFinish = serverLoginFinish(
            serverLoginStart.serverLogin,
            clientLoginFinish.credentialFinalization,
            context,
            clientId,
            serverId,
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
