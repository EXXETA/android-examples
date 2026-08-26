package com.example.nav3todo.ui.editor

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.time.LocalDate

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TodoEditScreen(
    todoId: Long?,
    onSaved: () -> Unit,
    onCancel: () -> Unit,
    viewModel: TodoEditViewModel = hiltViewModel(),
) {
    val isEditMode = todoId!=null
    val existingTodo by viewModel.existingTodo(todoId)
        .collectAsStateWithLifecycle(initialValue = null)

    var title by remember { mutableStateOf("") }
    var isDone by remember { mutableStateOf(false) }
    var dueDateText by remember { mutableStateOf("") } // simple text input, format: yyyy-MM-dd

    // Once the existing item loads (edit mode), populate the form fields once.
    LaunchedEffect(existingTodo) {
        existingTodo?.let { todo ->
            title = todo.title
            isDone = todo.isDone
            dueDateText = todo.dueDate?.toString() ?: ""
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (isEditMode) "Edit Todo" else "Add Todo") },
                navigationIcon = {
                    IconButton(onClick = onCancel) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Cancel")
                    }
                },
                actions = {
                    IconButton(onClick = {
                        val parsedDate = dueDateText.takeIf { it.isNotBlank() }?.let {
                            runCatching { LocalDate.parse(it) }.getOrNull()
                        }
                        if (isEditMode) {
                            existingTodo?.let { current ->
                                viewModel.updateTodo(
                                    current.copy(
                                        title = title,
                                        isDone = isDone,
                                        dueDate = parsedDate
                                    )
                                )
                            }
                        } else {
                            viewModel.addTodo(title = title, dueDate = parsedDate)
                        }
                        onSaved()
                    }) {
                        Icon(Icons.Filled.Check, contentDescription = "Save")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                label = { Text("Title") },
                modifier = Modifier.fillMaxWidth()
            )
            androidx.compose.foundation.layout.Spacer(modifier = Modifier.padding(top = 16.dp))
            OutlinedTextField(
                value = dueDateText,
                onValueChange = { dueDateText = it },
                label = { Text("Due date (yyyy-MM-dd)") },
                modifier = Modifier.fillMaxWidth()
            )
            androidx.compose.foundation.layout.Spacer(modifier = Modifier.padding(top = 16.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Done")
                androidx.compose.foundation.layout.Spacer(modifier = Modifier.padding(start = 8.dp))
                Switch(checked = isDone, onCheckedChange = { isDone = it })
            }
        }
    }
}
