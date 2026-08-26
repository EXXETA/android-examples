package com.example.nav3todo.navigation

import androidx.compose.material3.adaptive.ExperimentalMaterial3AdaptiveApi
import androidx.compose.material3.adaptive.navigation3.ListDetailSceneStrategy
import androidx.navigation3.runtime.NavEntry
import androidx.navigation3.runtime.entryProvider
import com.example.nav3todo.ui.detail.TodoDetailScreen
import com.example.nav3todo.ui.editor.TodoEditScreen
import com.example.nav3todo.ui.list.EmptyDetailPlaceholder
import com.example.nav3todo.ui.list.TodoListScreen

@OptIn(ExperimentalMaterial3AdaptiveApi::class)
fun buildEntryProvider(nav: AppNavViewModel): (AppDestination) -> NavEntry<AppDestination> =
    entryProvider {
        entry<AppDestination.TodoList>(
            metadata = ListDetailSceneStrategy.listPane(
                detailPlaceholder = { EmptyDetailPlaceholder() }
            )
        ) {
            TodoListScreen(
                onTodoClick = nav::openDetail,
                onAddClick = nav::openEdit,
            )
        }
        entry<AppDestination.TodoDetail>(
            metadata = ListDetailSceneStrategy.detailPane()
        ) { key ->
            TodoDetailScreen(
                todoId = key.id,
                onEditClick = { nav.openEdit(key.id) },
                onBack = nav::goBack
            )
        }
        entry<AppDestination.TodoEdit>(
            metadata = ListDetailSceneStrategy.detailPane()
        ) { key ->
            TodoEditScreen(
                todoId = key.id,
                onSaved = nav::goBack,
                onCancel = nav::goBack
            )
        }
    }
