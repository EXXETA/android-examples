package com.example.nav3todo

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.navigation3.runtime.deeplink.DeepLinkRequest
import androidx.navigation3.runtime.deeplink.invoke
import com.example.nav3todo.navigation.AppNavViewModel
import com.example.nav3todo.navigation.DeepLinkParser
import com.example.nav3todo.ui.theme.Nav3TodoTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    private val navViewModel: AppNavViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIntent(intent)
        setContent {
            Nav3TodoTheme {
                Nav3TodoApp()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        val syntheticBackStack = DeepLinkParser.parse(DeepLinkRequest(intent)) ?: return
        navViewModel.handleDeepLink(syntheticBackStack)
    }
}
