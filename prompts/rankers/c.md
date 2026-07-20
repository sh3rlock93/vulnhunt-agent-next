---
language: c
---

Boost files that:

- parse untrusted text, binary formats, protocol messages, or command-line input;
- convert strings to integers or narrow values across signed/unsigned types;
- use attacker-influenced indices, lengths, offsets, allocation sizes, or loop bounds;
- call memcpy, memmove, strcpy, strcat, sprintf, scanf, malloc, realloc, free, or exec;
- implement ownership, reference counting, parser state, or callback dispatch;
- are lexer/parser sources (`.l`, `.y`) or their handwritten consumers.

Prioritize reachable input-to-memory-operation paths over isolated helper functions.
