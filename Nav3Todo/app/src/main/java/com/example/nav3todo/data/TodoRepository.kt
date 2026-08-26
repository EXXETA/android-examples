package com.example.nav3todo.data

import kotlinx.coroutines.flow.Flow
import java.time.LocalDate

class TodoRepository(private val dao: TodoDao) {

    fun getAll(): Flow<List<Todo>> = dao.getAll()

    fun getDueToday(): Flow<List<Todo>> = dao.getDueOn(LocalDate.now())

    fun getById(id: Long): Flow<Todo?> = dao.getById(id)

    suspend fun add(title: String, dueDate: LocalDate?): Long =
        dao.insert(Todo(title = title, dueDate = dueDate))

    suspend fun update(todo: Todo) = dao.update(todo)

    suspend fun toggleDone(todo: Todo) = dao.update(todo.copy(isDone = !todo.isDone))

    suspend fun delete(todo: Todo) = dao.delete(todo)
}
