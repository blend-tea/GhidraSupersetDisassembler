# Integration test fixtures

**English** | [日本語](README_ja.md)

`generate.py --output <directory>` generates Raw, ELF, and PE inputs in both CPU widths using only the Python standard library. No compiler or external disassembler is required.

Each file contains an entry function and a directly called function.

| Mode | Entry instruction offsets | Callee instruction offsets |
| --- | --- | --- |
| 32-bit | 0, 1, 3, 8, 10, 11 | 20, 21, 23, 24 |
| 64-bit | 0, 1, 4, 9, 11, 12 | 20, 21, 23, 24 |

The NOP padding between functions is unreachable from the entry. In the 64-bit fixture, offset 2 begins another valid instruction inside an executed instruction. The final Raw byte `0f` is an incomplete opcode. The 64-bit Raw and PE fixtures use addresses above 4 GiB to catch truncation to 32-bit integers.

ELF uses one executable PT_LOAD segment; PE uses one executable `.text` section. Expected results come from header addresses and known instruction labels, not from copying the implementation's disassembly output.
