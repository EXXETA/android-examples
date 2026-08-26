package com.example.nav3todo.ui.detail

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.nav3todo.data.Todo
import com.example.nav3todo.data.TodoRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed interface TodoDetailState {
    data object Loading : TodoDetailState
    data class Found(val todo: Todo) : TodoDetailState
    data object NotFound : TodoDetailState
}

@HiltViewModel
class TodoDetailViewModel @Inject constructor(
    private val repository: TodoRepository
) : ViewModel() {

    fun detailState(id: Long): Flow<TodoDetailState> =
        repository.getById(id).map { todo ->
            if (todo!=null) TodoDetailState.Found(todo) else TodoDetailState.NotFound
        }

    fun deleteTodo(todo: Todo) = viewModelScope.launch { repository.delete(todo) }
}
