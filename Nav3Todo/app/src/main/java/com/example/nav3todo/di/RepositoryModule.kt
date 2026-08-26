package com.example.nav3todo.di

import com.example.nav3todo.data.TodoDao
import com.example.nav3todo.data.TodoRepository
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object RepositoryModule {

    @Provides
    @Singleton
    fun provideTodoRepository(dao: TodoDao): TodoRepository = TodoRepository(dao)
}
