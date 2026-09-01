package com.example.nav3todo.navigation

import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient


/**
 * Base type for all screens in this app's back stack.
 */
@Serializable
sealed interface AppDestination : NavKey {
    val parent: AppDestination? get() = null

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
 */
interface DeepLinkDestination : AppDestination
