package com.example.opaque_demo

import android.app.Application
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.opaque_demo.network.OpaqueService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import se.digg.wallet.access_mechanism.api.OpaqueClient
import java.io.InputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class RegisterViewModel(application: Application) : AndroidViewModel(application) {

    private val service = OpaqueService()

    val clientIdentifier = "https://wallets/digg.se/1234567890"
    val serverIdentifier = "https://cloud-wallet.digg.se/rhsm"

    private val _result = MutableStateFlow<String?>(null)
    val result = _result.asStateFlow()

    val authorizationCode: ByteArray = ByteArray(16)

    private val opaqueApi: OpaqueClient by lazy {
        OpaqueClient(
            getServerPublicKey(),
            getClientPrivateKey(),
            getPinStretchPrivateKey(),
            clientIdentifier,
            serverIdentifier,
            "RPS-Ops"
        )
    }

    /**
     * Register the authentication code for the device
     * This should already be available on the server. This is just to be able to run a registerPin
     */
    fun registerAuthentication() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                SecureRandom().nextBytes(authorizationCode)

                val registerDeviceRequest = opaqueApi.registerDevice(authorizationCode)

                service.sendRequest(registerDeviceRequest)
                // We don't care about the result. This is just for testing
            } catch (e: Exception) {
                _result.value = "Device registration failed: ${e.message}"
            }
        }
    }

    /**
     * Register a pin (123) for the device
     */
    fun registerPin() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val pin = "123"
                val registrationStart = opaqueApi.registrationStart(pin)

                val registrationResponse =
                    service.sendRequest(registrationStart.registrationRequest)

                val registerFinish = opaqueApi.registrationFinish(
                    pin,
                    authorizationCode,
                    registrationResponse,
                    registrationStart.clientRegistration
                )

                val serverFinish = service.sendRequest(registerFinish.registrationUpload)

                val message = opaqueApi.getMessage(serverFinish)
                _result.value = message
            } catch (e: Exception) {
                _result.value = "Registration failed: ${e.message}"
            }
        }
    }

    fun createSession() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val pin = "123"
                val loginStart = opaqueApi.loginStart(pin)

                val serverStart = service.sendRequest(loginStart.loginRequest)

                val loginFinish = opaqueApi.loginFinish(
                    pin, serverStart, loginStart.clientRegistration
                )

                val serverFinish = service.sendRequest(loginFinish.loginFinishRequest)


                val message = opaqueApi.getMessage(serverFinish)
                check(message == "OK")
                _result.value = loginFinish.sessionKey.joinToString("") { "%02x".format(it) }
            } catch (e: Exception) {
                _result.value = "Login failed: ${e.message}"
            }
        }
    }

    private fun getServerPublicKey(): ECPublicKey {
        val inputStream: InputStream =
            getApplication<Application>().resources.openRawResource(R.raw.serverkey)
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(inputStream)
        return certificate.publicKey as ECPublicKey
    }

    private fun getClientPrivateKey(): ECPrivateKey {
        val password = "Test1234".toCharArray()
        val alias = "wallet-hsm"
        val keyStore = KeyStore.getInstance("PKCS12")
        getApplication<Application>().resources.openRawResource(R.raw.wallethsm)
            .use { inputStream ->
                keyStore.load(inputStream, password)
            }
        return keyStore.getKey(alias, password) as ECPrivateKey
    }

    private fun getPinStretchPrivateKey(): PrivateKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }
        val keyAlias = "pinstretchkey"

        if (!keyStore.containsAlias(keyAlias)) {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )
            val parameterSpec = KeyGenParameterSpec.Builder(
                keyAlias, KeyProperties.PURPOSE_AGREE_KEY
            ).setAlgorithmParameterSpec(
                ECGenParameterSpec("secp256r1")
            ).build()

            generator.initialize(parameterSpec)
            generator.generateKeyPair()
        }
        return keyStore.getKey(keyAlias, null) as PrivateKey
    }
}