package com.example.nav3todo.data

import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.room.RoomDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.time.LocalDate
import javax.inject.Inject
import javax.inject.Provider

/**
 * Seeds the database with sample todos the first time it's created (fresh install,
 * or after clearing app data). `onCreate` only fires once — when the underlying
 * SQLite file didn't already exist.
 */
class DatabaseInitializer @Inject constructor(
    private val todoDaoProvider: Provider<TodoDao>
) : RoomDatabase.Callback() {

    private val applicationScope = CoroutineScope(SupervisorJob())

    override fun onCreate(db: SupportSQLiteDatabase) {
        super.onCreate(db)
        applicationScope.launch(Dispatchers.IO) {
            val dao = todoDaoProvider.get()
            val today = LocalDate.now()

            listOf(
                Todo(title = "Submit expense report", isDone = false, dueDate = today),
                Todo(title = "Water the plants", isDone = true, dueDate = today),
                Todo(title = "Team retro at 3pm", isDone = false, dueDate = today),
                Todo(title = "Call the dentist", isDone = false, dueDate = today.minusDays(1)),
                Todo(title = "Prepare slides for standup", isDone = false, dueDate = today.plusDays(1)),
                Todo(title = "Renew car insurance", isDone = false, dueDate = today.plusWeeks(1)),
                Todo(title = "Book flights for conference", isDone = true, dueDate = today.plusWeeks(2)),
                Todo(title = "Read \"Effective Kotlin\"", isDone = false, dueDate = null),
                Todo(title = "Clean up old branches", isDone = false, dueDate = null),
            ).forEach { dao.insert(it) }
        }
    }
}
