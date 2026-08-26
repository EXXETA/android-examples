package com.example.nav3todo.ui.list

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CalendarToday
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.nav3todo.data.Todo
import com.example.nav3todo.domain.TodoFilter
import java.time.LocalDate

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TodoListScreen(
    onTodoClick: (Long) -> Unit,
    onAddClick: () -> Unit,
    viewModel: TodoListViewModel = hiltViewModel(),
) {
    val filter by viewModel.filter.collectAsStateWithLifecycle()
    val todos by viewModel.todos.collectAsStateWithLifecycle()
    val groupedTodos = remember(todos) {
        todos.groupBy { it.dueDate }.toSortedMap(compareBy { it ?: LocalDate.MAX })
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text(if (filter==TodoFilter.Today) "Due Today" else "All Todos") })
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onAddClick) {
                Icon(Icons.Filled.Add, contentDescription = "Add todo")
            }
        }
    ) { padding ->
        Column(Modifier.padding(padding)) {
            Row(Modifier.padding(8.dp)) {
                FilterChip(
                    selected = filter==TodoFilter.All,
                    onClick = { viewModel.setFilter(TodoFilter.All) },
                    label = { Text("All") }
                )
                Spacer(Modifier.width(8.dp))
                FilterChip(
                    selected = filter==TodoFilter.Today,
                    onClick = { viewModel.setFilter(TodoFilter.Today) },
                    label = { Text("Today") }
                )
            }
            LazyColumn(contentPadding = PaddingValues(bottom = 80.dp)) {
                groupedTodos.forEach { (date, todosForDate) ->
                    item(key = "header-${date ?: "none"}") {
                        Text(
                            text = date?.toString() ?: "No due date",
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                        )
                    }
                    items(todosForDate, key = { it.id }) { todo ->
                        TodoRow(
                            todo = todo,
                            onClick = { onTodoClick(todo.id) },
                            onToggleDone = { viewModel.toggleDone(todo) }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun TodoRow(
    todo: Todo,
    onClick: () -> Unit,
    onToggleDone: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp)
            .clickable { onClick() },
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Checkbox(checked = todo.isDone, onCheckedChange = { onToggleDone() })
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    text = todo.title,
                    style = MaterialTheme.typography.bodyLarge,
                    textDecoration = if (todo.isDone) TextDecoration.LineThrough else null
                )
                if (todo.dueDate!=null) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Filled.CalendarToday,
                            contentDescription = null,
                            modifier = Modifier.size(14.dp),
                            tint = MaterialTheme.colorScheme.outline
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(
                            text = todo.dueDate.toString(),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.outline
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun EmptyDetailPlaceholder() {
    Surface(modifier = Modifier.fillMaxSize()) {
        Box(contentAlignment = Alignment.Center) {
            Text("Select a todo to see details")
        }
    }
}
