package com.example.opaque_demo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.opaque_demo.ui.theme.Opaque_demoTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            Opaque_demoTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Buttons(
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }
}

@Composable
fun Buttons(modifier: Modifier = Modifier, viewModel: RegisterViewModel = viewModel()) {
    Column(
        modifier = modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        val result by viewModel.result.collectAsState()
        val scope = rememberCoroutineScope()


        Button(onClick = { viewModel.registerPin() }) {
            Text(text = "Register pin")
        }
        Button(onClick = { viewModel.createSession() }) {
            Text(text = "Create session")
        }
        Button(onClick = { viewModel.createHsmKey() }) {
            Text(text = "Create HSM key")
        }
        Button(onClick = {
            scope.launch {
                viewModel.listHsmKey()
            }
        }) {
            Text(text = "List HSM keys")
        }
        // todo sign and deleteKey will eventually need a key as input.
        Button(onClick = {
            scope.launch {
                viewModel.sign()
            }
        }) {
            Text(text = "Sign")
        }
        Button(onClick = { viewModel.deleteKey() }) {
            Text(text = "Delete HSM key")
        }

        result?.let {
            Text(text = it)
        }
    }
}