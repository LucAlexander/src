# Src

<p align="center">
    <img src="https://github.com/LucAlexander/src/blob/master/logo.png?raw=true" alt="logo">
</p>


Check the included src files in the repository for examples, some of them are older as the system has gone through a few phases of iteration. These docs are minimal and will improve as the spec solidifies.

Source is a metacomputation tool. It can serve as a standalone virtual computer, but can be used as a plugin manager for basically any base language. You define syntactic mutations to your file in a well defined language of computation close to how real computation happens on real machines, and can then define semantic state for those syntactic constructs in the same language. A runtime language exists alonside the compile time system, of course also in the same language. True unbounded freedom, allowing absolute precision. Ever want assembly with a proof engine tacked on? Now you can make it. 

You can run multiple instances of source computers in the same directory and have them communicate over an emulated network via file io.

## Passes

Passes handle the syntactic side of metaprogramming. They operate on the program file memory itself inside a vm. r0 is given the address of the source program, r1 is the address of the start of the output program, which replaces your program when the pass runs. 

```
pass
mov 0 r1
bind continue ip
	mov r2 r0
	movw r3 !/
	cmp [r0] r3
	jne append
	add r0 r0 !8
	cmp [r0] r3
	jne append
	bind inner ip
		add r0 r0 !8
		movw r3 !\
		cmp [r0] r3
		jne inner 
		add r0 r0 !8
		jmp continue 
	bind append ip
	mov r0 r2
	mov [r1] [r0]
	add r1 r1 !8
	add r0 r0 !8
	cmp r0 0
	jlt continue
bind break ip
mov r0 !1
int	
end

```

## Comptime

Comptime handles the semantic side of metaprogramming. It gives you a compile time vm to store persistent data accross comptime blocks.
```
comp
    anything here runs at comptile time
    mov r0 !1
    int
run
```

## Binds
```
comp
    mov r1 !FF
    mov r0 !1
    int
run

bind  hi_byte = r1
```
binds `hi_byte` to the constant stored in r1 on the comptime vm: `FF`.
```
unbind hi_byte
```
releases the binding.

## ISA

```
Builtin Regsiters = r0 | r1 | r2 | r3 | ip
Opcodes = mov loc loc
        | movw loc locw
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

loc = [deref] | literal32 | address
locw = literal64
deref = literal32 | address
address = (hex integer)
literal = !(hex integer)
```

## Interrupts

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

r0: 9
r1: instruction pointer for new core to start at
r0 <- core running, 0 for no core available

r0: a
r1: file network address word
r2: packet start address
r3: packet length (bytes)
send message to another src computer

r0: b
r1: address to dump network addresses
r2 <- number of addresses found

r0: c
r1: address to read message into
r2 <- length of message 
```

## Builtin Symbols
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
