package com.example.nav3todo.navigation

import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient


/**
 * Base type for all screens in this app's back stack.
 */
@Serializable
sealed interface AppDestination : NavKey {

    @Serializable
    data object TodoList : AppDestination

    @Serializable
    data class TodoDetail(val id: Long) : AppDestination, DeepLinkDestination {
        @Transient
        override val parent: AppDestination = TodoList
    }

    @Serializable
    data class TodoEdit(val id: Long? = null) : AppDestination, DeepLinkDestination {
        @Transient
        override val parent: AppDestination = TodoList
    }
}

/**
 * Marks a destination as being reachable via a deep link, and therefore requiring
 * a synthetic back stack to support natural Back/Up navigation (see the
 * "Deep linking simulates manual navigation" principle).
 *
 * [parent] should be the screen the user would most likely have seen right before
 * this destination, had they navigated to it manually within the app.
 */
interface DeepLinkDestination : AppDestination {
    val parent: AppDestination
}
