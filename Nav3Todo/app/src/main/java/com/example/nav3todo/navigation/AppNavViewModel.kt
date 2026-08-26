package com.example.nav3todo.navigation

import androidx.lifecycle.ViewModel
import androidx.navigation3.runtime.NavBackStack
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

@HiltViewModel
class AppNavViewModel @Inject constructor() : ViewModel() {

    val backStack: NavBackStack<AppDestination> = NavBackStack(AppDestination.TodoList)

    fun openDetail(id: Long) {
        popUpToStart()
        backStack.add(AppDestination.TodoDetail(id))
    }

    fun openEdit(id: Long? = null) {
        if (id==null) popUpToStart()
        backStack.add(AppDestination.TodoEdit(id))
    }

    fun goBack(): Boolean {
        if (backStack.size <= 1) return false
        backStack.removeAt(backStack.lastIndex)
        return true
    }

    private fun popUpToStart() {
        while (backStack.size > 1) {
            backStack.removeAt(backStack.lastIndex)
        }
    }

    fun handleDeepLink(syntheticBackStack: List<AppDestination>) {
        backStack.clear()
        backStack.addAll(syntheticBackStack)
    }
}
