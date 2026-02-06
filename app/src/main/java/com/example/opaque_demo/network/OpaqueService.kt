package com.example.opaque_demo.network

import android.util.Log
import com.example.opaque_demo.BffRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException

class OpaqueService {

    private val client = OkHttpClient()
    private val baseUrl = "http://10.0.2.2:8088/r2ps-api/service"

    suspend fun sendRequest(bffRequest: BffRequest): String {
        return withContext(Dispatchers.IO) {
            val mediaType = "application/json; charset=utf-8".toMediaType()
            val jsonString = Json.encodeToString(bffRequest)
            val body = jsonString.toRequestBody(mediaType)
            val request = Request.Builder().url(baseUrl).post(body).build()

            try {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        Log.e("OpaqueDemo", "Unexpected code $response")
                        throw IOException("Unexpected code $response")
                    } else {
                        val responseString = response.body.string()
                        Log.d("OpaqueDemo", "Response: $responseString")
                        responseString
                    }
                }
            } catch (e: IOException) {
                Log.e("OpaqueDemo", "Network error", e)
                throw e
            }
        }
    }
}
