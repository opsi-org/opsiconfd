# Standards for writing Git commit messages

## Format of commit messages
Each commit message **must** begin with a list of tags inside square brackets, separated by commas, i.e. `[chg]`.

- The first tag is **always required** and specifies the **type** of change. Allowed values are:
  - `chg`: Change to existing functionality
  - `new`: New feature
  - `fix`: Bug fix
  - `rem`: Removal of functionality
  - `dep`: Deprecation of functionality
  - `sec`: Security update

- Optionally, add the `pub` tag as the second tag if the change should appear in public release notes.
Use `pub` only for changes that are important for users to know about.

After the tags, add a single space, then write the **subject** — a short, imperative summary of the change (for example: "Update user authentication logic").

If needed, add a blank line after the subject, followed by a more detailed description of the change.

## Python package updates

If Python packages were updated (i.e., changes to the uv.lock file), use this commit message format:

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
