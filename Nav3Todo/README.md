# Nav3Todo

A small, complete Todo app built to
explore [Jetpack Navigation 3](https://developer.android.com/guide/navigation/navigation-3) — used
as the companion project for the Medium article _"Jetpack Navigation 3: A Practical Guide to Deep
Links and Beyond"_.
This project isn't meant to be a production-grade todo app. It's a focused sandbox for exercising
Navigation 3's core APIs, deep linking, and adaptive list-detail layouts, with realistic (but
intentionally minimal) supporting infrastructure like Room persistence and Hilt DI.

## Features

* **Todo list** with add / edit / delete / mark-as-done

* **Filtering** — view all todos or only those due today

* **Date grouping** — todos are grouped by due date in the list

* **Deep linking** — `nav3todo://todos/{id}` opens a specific todo directly, with a correctly
  reconstructed back stack

* **Adaptive list-detail layout** — list and detail panes render side-by-side on wide screens (
  tablets, unfolded foldables), and stack normally on phones

* **Custom transitions & predictive back** — slide animations for push/pop navigation, including
  predictive back gesture support

* **Pre-seeded sample data** — the database is populated with example todos on first launch

## Tech Stack

* **Jetpack Compose** — UI toolkit

* **Navigation 3** (`androidx.navigation3`) — navigation, back stack management, deep linking (
  `UriDeepLinkMatcher`, `DeepLinkMatcher.withBackStack`)

* **Material 3 Adaptive** (`androidx.compose.material3.adaptive`) — `ListDetailSceneStrategy` for
  the adaptive layout

* **Room** — local persistence for todos

* **Hilt** — dependency injection

* **kotlinx.serialization** — required by Navigation 3 for `NavKey` serialization and deep link
  matching

## Architecture Overview

```
com.example.nav3todo/
├── data/                   # Room entities, DAO, database, repository, seed data
├── di/                     # Hilt modules
├── domain/                 # Domain enums (e.g. TodoFilter)
├── navigation/
│   ├── AppDestination.kt   # Sealed NavKey hierarchy (TodoList, TodoDetail, TodoEdit)
│   ├── AppNavViewModel.kt  # Owns the NavBackStack, exposes navigation actions
│   ├── AppEntryProvider.kt # Maps each AppDestination to its @Composable content
│   ├── DeepLinkParser.kt   # UriDeepLinkMatcher + synthetic back stack construction
│   └── SyntheticBackStack.kt
├── ui/
│   ├── list/                # TodoListScreen + TodoListViewModel
│   ├── detail/              # TodoDetailScreen + TodoDetailViewModel
│   └── editor/              # TodoEditScreen + TodoEditViewModel
├── MainActivity.kt          # Deep link entry point (onCreate / onNewIntent)
└── Nav3TodoApp.kt           # Root composable, NavDisplay + adaptive scene strategy setup
```

Each screen has its own dedicated `ViewModel` (list, detail, editor), rather than sharing one across
the app — this keeps navigation-triggered state (like the list's filter, or the detail screen's "not
found" state) isolated to where it's actually used.

## Navigation Model

The back stack is held in `AppNavViewModel` rather than via `rememberNavBackStack(...)`,
specifically so it can be read and modified from `MainActivity.onCreate()` — before Compose even
runs — in order to handle incoming deep links before the UI is composed.
Key navigation actions:

```kotlin
fun openDetail(id: Long)          // navigates to a todo's detail screen
fun openEdit(id: Long? = null)    // null = add new todo, non-null = edit existing
fun goBack(): Boolean
fun handleDeepLink(syntheticBackStack: List<AppDestination>)
```

`openDetail` and `openEdit(id = null)` call `popUpToStart()` first, collapsing any existing
detail-pane content before pushing a new selection. This matters most in the adaptive layout (
selecting a different item from the still-visible list pane shouldn't grow the back stack
indefinitely), but benefits single-pane navigation too.

## Deep Linking

Supported deep link:

```
nav3todo://todos/{id}
```

Matching is done via `UriDeepLinkMatcher` against the `TodoDetail` navigation key, wrapped with
`DeepLinkMatcher.withBackStack { }` to reconstruct a synthetic back stack (
`[TodoList, TodoDetail(id)]`) rather than landing on the detail screen with an empty stack.

### Testing deep links

Via `adb`:

```bash
adb shell am start -a android.intent.action.VIEW -d "nav3todo://todos/1"
```

Via Android Studio: Run/Debug Configurations → Launch Options → Launch: **URL** → enter
`nav3todo://todos/1`.
For manifest validation and (if you extend this to real `https://` App Links) `assetlinks.json`
generation, use **Tools → App Links Assistant**.

## Adaptive Layout

The list and detail panes are marked via `entry<T>(metadata = ...)`:

```kotlin
entry<AppDestination.TodoList>(
    metadata = ListDetailSceneStrategy.listPane(
        detailPlaceholder = { Text("Select a todo to see details") }
    )
) { /* ... */ }

entry<AppDestination.TodoDetail>(
    metadata = ListDetailSceneStrategy.detailPane()
) { /* ... */ }
```

`TodoDetail` and `TodoEdit` both occupy the detail pane — from the layout's perspective, editing is
just different content in the same pane the detail view was already showing.

## Setup

1. Clone the repository and open it in Android Studio.

2. Sync Gradle — dependencies include Navigation 3, Room, Hilt, kotlinx.serialization, and Material
   3 Adaptive (see `libs.versions.toml` for exact versions).

3. Run the app. On first launch, the database is seeded automatically with sample todos (see
   `DatabaseInitializer`).

4. To reset the seed data, clear the app's storage (Settings → Apps → Nav3Todo → Storage → Clear
   storage) and relaunch.

**Requirements:** minSdk 26 (required by `LocalDate.toEpochDay()` used for due dates).

## Known Limitations

* No authentication, sync, or remote data source — purely local persistence.

* No support for cross-app deep linking / full Up-button task restart behavior (
  `TaskStackBuilder`) — see the [official](https://github.com/android/nav3-recipes) `nav3-recipes`
  repository if you need that.

* Several dependencies (Navigation 3, Material 3 Adaptive Navigation 3) are in alpha at the time of
  writing; expect API changes on upgrade.

## Related Article

This project accompanies a [Medium article](#) covering Navigation 3's core concepts, deep linking
in
depth, and adaptive list-detail layouts. _(Link to article pending)_

## License

MIT — see [LICENSE](LICENSE) for details.
