#!/usr/bin/env python3
"""PreToolUse hook for Bash: deny `cd`, `pushd`, and `popd`.

Reads the hook input JSON on stdin and writes a PreToolUse decision on stdout.
The hook input's `cwd` is the session directory, and the hook input omits a command's `workdir`, so after a `cd`, or with `workdir` set, the other hooks judge the command against the wrong directory.
A `cd` does not carry over to the next command either: Codex starts every command in the session directory, or in the `workdir` the command sets.
A command that names its directories, with absolute paths or a program's directory flag, does the same thing whatever directory it starts in.
"""

from shell_parsing import deny, program_name, read_input, resolve_head, split_segments

DIRECTORY_CHANGERS = {"cd", "pushd", "popd"}


def verdict(segment):
    """Return the name of the directory-changing command this segment runs, or None."""
    word, _ = resolve_head(segment.text)
    if word is None:
        return None
    name = program_name(word)
    return name if name in DIRECTORY_CHANGERS else None


def main():
    command, _ = read_input()
    for segment in split_segments(command):
        name = verdict(segment)
        if name:
            deny(
                f"`{name}` changes the directory the rest of the command runs in, which the hooks cannot see. "
                "Use absolute paths, or the program's own directory flag (`git -C <dir>`, `uv run --directory <dir>`)."
            )


if __name__ == "__main__":
    main()
