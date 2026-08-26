package com.example.nav3todo

import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.adaptive.ExperimentalMaterial3AdaptiveApi
import androidx.compose.material3.adaptive.navigation3.rememberListDetailSceneStrategy
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.navigation3.ui.NavDisplay
import com.example.nav3todo.navigation.AppDestination
import com.example.nav3todo.navigation.AppNavViewModel
import com.example.nav3todo.navigation.buildEntryProvider

@OptIn(ExperimentalMaterial3AdaptiveApi::class)
@Composable
fun Nav3TodoApp() {
    val navViewModel: AppNavViewModel = hiltViewModel()
    val listDetailStrategy = rememberListDetailSceneStrategy<AppDestination>()

    NavDisplay(
        backStack = navViewModel.backStack,
        onBack = navViewModel::goBack,
        sceneStrategies = listOf(listDetailStrategy),
        transitionSpec = {
            // Slide in from right when navigating forward
            slideInHorizontally(initialOffsetX = { it }) togetherWith
                slideOutHorizontally(targetOffsetX = { -it })
        },
        popTransitionSpec = {
            // Slide in from left when navigating back
            slideInHorizontally(initialOffsetX = { -it }) togetherWith
                slideOutHorizontally(targetOffsetX = { it })
        },
        predictivePopTransitionSpec = {
            // Slide in from left when navigating back
            slideInHorizontally(initialOffsetX = { -it }) togetherWith
                slideOutHorizontally(targetOffsetX = { it })
        },
        modifier = Modifier.background(MaterialTheme.colorScheme.background),
        entryProvider = buildEntryProvider(navViewModel)
    )
}
