package com.example.nav3todo.navigation

import androidx.core.net.toUri
import androidx.navigation3.runtime.deeplink.DeepLinkRequest
import androidx.navigation3.runtime.deeplink.UriDeepLinkMatcher
import androidx.navigation3.runtime.deeplink.withBackStack
import kotlinx.serialization.serializer

private const val TODO_DETAIL_PATTERN = "nav3todo://todos/{id}"

object DeepLinkParser {

    private val detailMatcher =
        UriDeepLinkMatcher(TODO_DETAIL_PATTERN.toUri(), serializer<AppDestination.TodoDetail>())
            .withBackStack { matchResult ->
                buildSyntheticBackStack(matchResult.key)
            }

    /** Returns the synthetic back stack for the matched deep link, or null if no match. */
    fun parse(request: DeepLinkRequest): List<AppDestination>? =
        detailMatcher.match(request)?.backStack
}
