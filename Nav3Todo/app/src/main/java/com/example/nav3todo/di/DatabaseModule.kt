package com.example.nav3todo.di

import android.content.Context
import androidx.room.Room
import com.example.nav3todo.data.AppDatabase
import com.example.nav3todo.data.DatabaseInitializer
import com.example.nav3todo.data.TodoDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideDatabase(
        @ApplicationContext context: Context,
        initializer: DatabaseInitializer
    ): AppDatabase =
        Room.databaseBuilder(context, AppDatabase::class.java, "nav3todo.db")
            .addCallback(initializer)
            .build()

    @Provides
    fun provideTodoDao(database: AppDatabase): TodoDao = database.todoDao()
}
