#!/bin/sh

set -xe

if [[ $1 == "--check" ]]; then
	find . -type f \( -name "*.c" -o -name "*.h" \) -exec clang-format -style=file --dry-run -Werror {} +
	exit 0
fi

# clang-format -style="{BasedOnStyle: LLVM, UseTab: Always, IndentWidth: 4, TabWidth: 4, PointerAlignment: Left, BreakBeforeBraces: Custom, BraceWrapping: {AfterControlStatement: MultiLine}}" -dump-config > .clang-format
find . -type f \( -name "*.c" -o -name "*.h" \) -exec clang-format -style=file -i {} +
