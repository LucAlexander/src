# Src

## Binds

```
bind 1 a {b}

a
```

evaluates to

```
b
```

### Keywords and Args

```
bind 1 a +x {b x}

a q
```

evaluates to

```
b q
```

`-x` means dont match pattern if x is present

Patterns can be specified: ` +x:\{ ... \} ` matches everything in between `{}` and binds it to pattern argument `x`

### Grouping

Grouping requires an opening character and a closing character separated by `...` like is visible in the above example.

### Alternates

Alternates allow you to match one of a selection of subpatterns.
```
bind 1 +x:[A | B | C] {
    [ case of A
    | case of B
    | case of C
    ]
    x
}

B

```

evaluates to

```
case of B

B
```

### Variadics

Variadics allows you to match delimeter separated lists
```
bind 1 def +fn_name( +arg_list:{+type:[int | float] +name ,} ) {
    fn_name:
    arglist{
        type[ push_u32 name
            | push_f64 name
        ]
    }
}

def sum(int a, float b)

```

Evaluates to:
```
sum:
push_u32 a
push_f64 b
```

### Byte Sequences

Grouping requires an opening character and a closing character separated by `,,,` like is visible in the grouping example.
```

bind 1 +string:\" ,,, \" {
    print("string")
}

"hello world"

```

Evaluates to:
```
print("hello world")
```

## Bytecode
The bytecode language designed for src is optional, and the tool can be used headless as a plugin system for any other language.

### Comptime
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

#### Builtin Regsiters: `r0 r1 r2 r3 ip`


### Builtin Symbols
