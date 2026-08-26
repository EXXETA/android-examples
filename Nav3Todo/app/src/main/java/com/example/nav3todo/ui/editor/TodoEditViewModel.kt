package com.example.nav3todo.ui.editor

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.nav3todo.data.Todo
import com.example.nav3todo.data.TodoRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
import java.time.LocalDate
import javax.inject.Inject

@HiltViewModel
class TodoEditViewModel @Inject constructor(
    private val repository: TodoRepository
) : ViewModel() {

    fun existingTodo(id: Long?): Flow<Todo?> =
        if (id!=null) repository.getById(id) else flowOf(null)

    fun addTodo(title: String, dueDate: LocalDate?) = viewModelScope.launch {
        repository.add(title, dueDate)
    }

    fun updateTodo(todo: Todo) = viewModelScope.launch { repository.update(todo) }
}
