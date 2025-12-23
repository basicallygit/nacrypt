#!/bin/sh

set -xe

# Prefer clang-format-20 if it exists
if command -v clang-format-20 >/dev/null 2>&1; then
	CLANG_FORMAT="clang-format-20"
elif command -v clang-format >/dev/null 2>&1; then
	CLANG_FORMAT="clang-format"
else
	echo "No clang-format found in PATH" >&2
	exit 1
fi

if [[ $1 == "--check" ]]; then
	find . -type f \( -name "*.c" -o -name "*.h" \) -exec $CLANG_FORMAT -style=file --dry-run -Werror {} +
	exit 0
fi

# clang-format -style="{BasedOnStyle: LLVM, UseTab: Always, IndentWidth: 4, TabWidth: 4, PointerAlignment: Left, BreakBeforeBraces: Custom, BraceWrapping: {AfterControlStatement: MultiLine}}" -dump-config > .clang-format
find . -type f \( -name "*.c" -o -name "*.h" \) -exec $CLANG_FORMAT -style=file -i {} +
