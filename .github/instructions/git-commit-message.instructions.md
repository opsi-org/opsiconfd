# Standards for writing Git commit messages

Use the following format for Git commit messages:

```
\[<type>[,pub]\] <subject>

<details>
```
- **type**: The type of change being made. Available types are:
  - `chg`: A change to existing functionality
  - `new`: A new feature
  - `fix`: A bug fix
  - `rem`: A removal of functionality
  - `dep`: A deprecation of functionality
  - `sec`: A security-related change
- **pub**: Optional. If included, indicates that the change is added to the public release notes.
- **subject**: A brief description of the change, written in the imperative mood (e.g., "Fix bug in user authentication").
- **details**: Optional. A more detailed description of the change, including any relevant context or information.

If Python packages were updated (changes were made to the uv.lock file), use the following commit message format:

```
[chg] Update python packages

Updated <package1> <old_version> -> <new_version>
Updated <package2> <old_version> -> <new_version>
...

```

## Example commit messages:
```
[chg] Update user authentication logic

- Refactor the user authentication logic to improve performance.
- Add unit tests for the new logic.
```

```
[chg,pub] Set parent group to NULL if it does not exist

Automatically set the parent group to NULL if it does not exist in the database.
```

```
[chg] Update python packages

Updated aiohttp v3.11.18 -> v3.12.7
Updated click v8.2.0 -> v8.2.1
Updated configargparse v1.7 -> v1.7.1
Updated coverage v7.8.0 -> v7.8.2
Updated cryptography v45.0.2 -> v45.0.3
```