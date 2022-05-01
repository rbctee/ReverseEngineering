# Using GDB

You can use the command `starti` to break on the first instruction of the program.

After that, to print the instructions:

```txt
# Show the next 5 instructions
(gdb) x/5i $pc
```
