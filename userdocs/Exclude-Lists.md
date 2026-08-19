# Exclude Lists

`SNAPSHOT ... EXCLUDE=<path>` skips files and directories you never want
backed up -- a Workbench cache directory, a `.info`-free scratch area, a
build's intermediate output. `<path>` is a plain-text file, one pattern
per line, read once at the start of the scan; a matching directory is
never even walked (nothing under it is examined at all), and a matching
file is simply never captured.

## File format

```
# lines starting with '#' are comments; blank lines are ignored
*.info
#?.bak
T/
Work/Projects/scratch
/Trash
log?.txt
```

- **Comments and blank lines** are ignored.
- **`*` and `?` wildcards**: `*` matches any run of characters
  (including none) within one path component; `?` matches exactly one
  character. Neither ever crosses a `/` -- a wildcard can't accidentally
  reach into an unrelated subtree.
- **AmigaDOS's own `#?` wildcard** is accepted as a synonym for `*` --
  same meaning, same rules (never crosses `/`), so a pattern typed the
  way AmigaDOS itself would show it (a Shell habit, or copied from a
  `List`/`Protect PAT=` argument) works exactly like the equivalent
  `*` pattern. `#?.bak` and `*.bak` exclude the same files. A `#` *not*
  immediately followed by `?` is unaffected -- still a comment marker
  at the start of a line, still just a literal character in the
  middle of one. Only that one two-character token is recognized; the
  rest of AmigaDOS's own pattern language (`%`, `(a|b)` alternation,
  `[...]` character classes, `~` negation) is not.
- **A pattern with no interior `/`** (e.g. `*.info`) matches against
  *any* path component at *any* depth -- it excludes an entry named
  that way wherever it occurs in the tree, not just at the source root.
- **A pattern with an interior or leading `/`** (e.g.
  `Work/Projects/scratch`, or `/Trash`) is anchored: it matches only
  that exact path relative to `SOURCE=`, nowhere else.
- **A trailing `/`** restricts the pattern to directories -- matching it
  excludes that directory and everything under it, but never a plain
  file of the same name.
- **Matching is case-insensitive** throughout. Every native Amiga
  filesystem AmiSnap targets (OFS, FFS, "international" FFS, PFS3) is
  case-preserving but case-insensitive, so a case-sensitive match could
  silently fail to exclude a file whose case happens to differ from
  what you typed -- the safer failure direction for an exclude list is
  "matched when it shouldn't have" (backs the file up anyway, no data
  lost), not the reverse.

## Example

Given a source tree:

```
Work:
  Projects/
    myapp/
      main.c
      main.o
    scratch/
  Icons.info
  T/
```

and an exclude file:

```
*.o
T/
Work/Projects/scratch
```

a `SNAPSHOT` of `Work:` with that `EXCLUDE=` captures `main.c` and
`Icons.info`, but skips `main.o` (matched by `*.o` at any depth), the
whole `T/` directory (matched by the trailing-`/` pattern -- note
`Icons.info` is unaffected, since `*.info` isn't in this particular
list and `T/`'s trailing slash means it only ever matches a directory
named exactly `T`), and the whole `Projects/scratch` subtree (matched by
the anchored pattern, which would NOT have matched a `scratch`
directory anywhere else in the tree).

## What the summary line reports

`SNAPSHOT`'s own summary line includes counts of excluded directories
and files, e.g.:

```
Snapshot 0000000000000605: 12 dirs, 340 files (338 unchanged, 0 failed), 0 links skipped, 2 dirs and 5 files excluded
```

so an `EXCLUDE=` list that's excluding more (or less) than you expect
is visible immediately, not silently absorbed into the ordinary file
count.
