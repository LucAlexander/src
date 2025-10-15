# Src

Check the included src files in the repository for examples, these docs are minimal and will improve as the spec solidifies.

## Binds

The bind system is a functional programming language layered on top of the bytecode, it handles the syntactic half of the metaprogramming.

```

pattern Comment = Comment '//' Anything_EOL;
pattern Anything_EOL = EOL '$' | Anything * Anything_EOL;

bind (Comment '//' anything) = ;


```

binds can be recursive and have where clauses containing local binds. They are preparsed but are applied sequentially. 

passing an argument in the form of `@name` to a bind creates a non argument that acts as a unique identifier that can be used during that bind.

## Bytecode
The bytecode language designed for src is optional, and the tool can be used headless as a plugin system for any other language, with comptime and run binds included.

### Comptime

Comptime handles the semantic side of metaprogramming.
```
comp
    anything here runs at comptile time
    move r0 !1
    int
run
```

### Run Binds
```
comp
    mov r1 !FF
    mov r0 !1
    int
run

bind 0 hi_byte = r1
```
binds `hi_byte` to the constant stored in r1 on the comptime vm: `FF`.

### ISA

```
Builtin Regsiters = r0 | r1 | r2 | r3 | ip
Opcodes = mov loc loc
        | movh loc loc
        | movl loc loc
        | add loc loc loc
        | sub loc loc loc
        | mul loc loc loc
        | div loc loc loc
        | mod loc loc loc
        | and loc loc loc
        | xor loc loc loc
        | or loc loc loc
        | shl loc loc loc
        | shr loc loc loc
        | not loc loc
        | com loc loc
        | cmp loc loc
        | jmp loc
        | jlt loc
        | jgt loc
        | jeq loc
        | jne loc
        | jle loc
        | jge loc
        | int

loc = [deref] | literal | address
deref = literal | address
address = (hex integer)
literal = !(hex integer)
```

### Interrupts

```
r0: 0
blit frame buffer to screen

r0: 1
end program execution

r0: 2
r1: value
print value to external stderr 

r0: 3
r1: key
r2 <- is key down

r0: 4
r1: key
r2 <- is key pressed

r0: 5
r1 <- mouse x
r2 <- mouse y

r0: 6
r1: mouse button
r2 <- is button down

r0: 7
r1: mouse button
r2 <- is button pressed

r0: 8
r1: in address of program
r2: in length of program
r3 <- address to write compiled program
```

### Builtin Symbols
```
mtp: memory top
mbm: memory bottom (frame buffer_size)
fbw: frame buffer width
fbh: frame buffer height 
SRC_MOUST_LEFT
SRC_MOUSE_RIGHT
SRC_MOUSE_MIDDLE
SRC_Q - M
SRC_LEFT RIGHT UP DOWN
SRC_SPACE
```
