# Permsearch

A very simple audit tool for finding files and folders in a directory (and its subdirectories) which don't have the expected owners and/or permissions.

## Features

Allowlist based search

- File/Directory permissions
- Owner (user and group)
- A combination of owner & permissions

## Usage

```text
Simple search for finding mistakes in filesystem owner and permission settings

Usage: permsearch [OPTIONS] <BASE_DIR>

Arguments:
  <BASE_DIR>
          Base directory to work upon

Options:
  -d, --directory-filter <DIRECTORY_FILTER>
          List of allowed directory types

  -f, --file-filter <FILE_FILTER>
          List of allowed file types

  -s, --silent
          Remove active config from output

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

### Filters

```text
-d, --directory-filter <DIRECTORY_FILTER>
          List of allowed directory types

-f, --file-filter <FILE_FILTER>
        List of allowed file types
```

```text
<ALLOWED_PERMISSIONS><USER><GROUP>

ALLOWED_PERMISSIONS: e.g. rwxr-*--- (user|group|other)
  r/w/x : set
      - : not set
      * : wildcard / ignore

               USER: e.g. u1000 (u<ID>)

              GROUP: e.g. g1000 (g<ID>)
```

Multiple filters can be joined with a `,`. All filters are then part of the same allowlist for the entire search.

A missing filter ignores the corresponding type.

If no filter is specified, the program searches for files and directories with different owner settings than the base directory. Permissions are ignored

### Output

Non-silent:

```console
$ permsearch -f u1001 -d u1001g1001 src
Base directory: "src"
Allowed (file): u1001

drwx------  1000  1000 src
-rw-r--r--  1000  1000 src/cli.rs
-rw-r--r--  1000  1000 src/input_parser.rs
-rw-r--r--  1000  1000 src/lib.rs
-rw-r--r--  1000  1000 src/main.rs
-rw-r--r--  1000  1000 src/util.rs
lrwx------  1000  1000 src/foo
```

Silent:

```console
$ permsearch -f u1001 -d u1001g1001 src -s
drwx------  1000  1000 src
-rw-r--r--  1000  1000 src/cli.rs
-rw-r--r--  1000  1000 src/input_parser.rs
-rw-r--r--  1000  1000 src/lib.rs
-rw-r--r--  1000  1000 src/main.rs
-rw-r--r--  1000  1000 src/util.rs
lrwx------  1000  1000 src/foo
```

> [!WARNING]
> Special permissions are currently ignored and are not part of the output
