package com.example.nav3todo.ui.list

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.nav3todo.data.Todo
import com.example.nav3todo.data.TodoRepository
import com.example.nav3todo.domain.TodoFilter
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class TodoListViewModel @Inject constructor(
    private val repository: TodoRepository
) : ViewModel() {

    private val _filter = MutableStateFlow(TodoFilter.All)
    val filter: StateFlow<TodoFilter> = _filter.asStateFlow()

    @OptIn(ExperimentalCoroutinesApi::class)
    val todos: StateFlow<List<Todo>> = _filter.flatMapLatest { currentFilter ->
            when (currentFilter) {
                TodoFilter.All -> repository.getAll()
                TodoFilter.Today -> repository.getDueToday()
            }
        }.stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = emptyList()
        )

    fun setFilter(newFilter: TodoFilter) {
        _filter.value = newFilter
    }

    fun toggleDone(todo: Todo) = viewModelScope.launch {
        repository.toggleDone(todo)
    }
}
