package com.example.nav3todo.data

import androidx.room.*
import kotlinx.coroutines.flow.Flow
import java.time.LocalDate

@Dao
interface TodoDao {

    @Query("SELECT * FROM todos ORDER BY dueDate IS NULL, dueDate ASC")
    fun getAll(): Flow<List<Todo>>

    @Query("SELECT * FROM todos WHERE dueDate = :date AND isDone = 0")
    fun getDueOn(date: LocalDate): Flow<List<Todo>>

    @Query("SELECT * FROM todos WHERE id = :id")
    fun getById(id: Long): Flow<Todo?>

    @Insert
    suspend fun insert(todo: Todo): Long

    @Update
    suspend fun update(todo: Todo)

    @Delete
    suspend fun delete(todo: Todo)
}
