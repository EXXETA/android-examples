package com.example.nav3todo.navigation

/**
 * Builds a synthetic back stack for [destination] by walking up its chain of
 * [DeepLinkDestination.parent] references, simulating the path a user would have
 * taken had they navigated to this destination manually, starting from the app's
 * start destination.
 *
 * Example: TodoDetail(42) -> [TodoList, TodoDetail(42)]
 */
fun buildSyntheticBackStack(destination: AppDestination): List<AppDestination> =
    buildList {
        add(destination)
        var current: AppDestination = destination
        while (current is DeepLinkDestination) {
            add(0, current.parent)
            current = current.parent
        }
    }
