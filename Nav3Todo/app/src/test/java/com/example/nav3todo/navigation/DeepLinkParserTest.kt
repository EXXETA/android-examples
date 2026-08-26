package com.example.nav3todo.navigation

import android.net.Uri
import com.example.nav3todo.domain.TodoFilter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DeepLinkParserTest {

    @Test
    fun `parses todo detail link`() {
        val uri = Uri.parse("nav3todo://todos/42")
        val result = DeepLinkParser.parse(uri)
        assertEquals(DeepLinkResult.Destination(AppDestination.TodoDetail(42)), result)
    }

    @Test
    fun `parses today filter link`() {
        val uri = Uri.parse("nav3todo://todos?filter=today")
        val result = DeepLinkParser.parse(uri)
        assertEquals(DeepLinkResult.FilterUpdate(TodoFilter.Today), result)
    }

    @Test
    fun `parses bare todos link as list`() {
        val uri = Uri.parse("nav3todo://todos")
        val result = DeepLinkParser.parse(uri)
        assertEquals(DeepLinkResult.Destination(AppDestination.TodoList), result)
    }

    @Test
    fun `returns null for unrelated scheme`() {
        val uri = Uri.parse("https://example.com/todos/42")
        assertNull(DeepLinkParser.parse(uri))
    }

    @Test
    fun `returns null for non-numeric id`() {
        val uri = Uri.parse("nav3todo://todos/abc")
        assertNull(DeepLinkParser.parse(uri))
    }
}
