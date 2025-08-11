const std = @import("std");
const Buffer = std.ArrayList;

pub fn main() !void {
	const allocator = std.heap.page_allocator;
	var infile = try std.fs.cwd().openFile("test.src", .{});
	defer infile.close();
	const stat = try infile.stat();
	const contents = try infile.readToEndAlloc(allocator, stat.size+1);
	defer allocator.free(contents);
	var main_mem = std.heap.ArenaAllocator.init(allocator);
	defer main_mem.deinit();
	const mem = main_mem.allocator();
	const tokens = tokenize(&mem, contents);
	show_tokens(tokens);
}

const TOKEN = enum {
	BIND, BIND_COMP, BIND_PATTERN,
	IDENTIFIER,
	OPEN_BRACK, CLOSE_BRACK,
	OPEN_BRACE, CLOSE_BRACE,
	ALTERNATE,
	ARGUMENT,
	IS_OF,
	ELIPSES,
	EXCLUSION,
	OPTIONAL,
	UNIQUE,
	HOIST,
	MOV,
	ADD, SUB, MUL, DIV, CMP,
	JMP,
	JLT, JGT, JLE, JGE,
	JZ, JNZ, JEQ, JNE,
	INT,
	IP, R0, R1, R2, R3,
	SPACE, NEW_LINE, TAB,
	LINE_START, LINE_END
};

const Token = struct {
	text: []u8,
	tag: TOKEN
};

const Arg = struct {
	tag: enum {
		inclusion, exclusion
	},
	name: Token,
	pattern: Pattern
};

const Pattern = union(enum) {
	token,
	keyword: Token,
	optional: *Pattern,
	alternate: Buffer(*Pattern),
	group: struct {
		open: *Pattern,
		close: *Pattern
	},
	variadic: struct {
		members: Buffer(Arg),
		separator: Arg
	},
};

const Bind = struct {
	tag: enum {
		rewrite,
		compile,
		pattern
	},
	precedence: u8,
	args: Buffer(Arg),
	text: []Token
};

const ProgramText = struct {
	text: []Token,
	binds: Buffer(Bind)
};

pub fn tokenize(mem: *const std.mem.Allocator, text: []u8) Buffer(Token) {
	var i: u64 = 0;
	var token_map = std.StringHashMap(TOKEN).init(mem.*);
	token_map.put("bind", .BIND) catch unreachable;
	token_map.put("bind_", .BIND_COMP) catch unreachable;
	token_map.put("_bind", .BIND_PATTERN) catch unreachable;
	token_map.put("...", .ELIPSES) catch unreachable;
	token_map.put("mov", .MOV) catch unreachable;
	token_map.put("add", .ADD) catch unreachable;
	token_map.put("sub", .SUB) catch unreachable;
	token_map.put("mul", .MUL) catch unreachable;
	token_map.put("div", .DIV) catch unreachable;
	token_map.put("cmp", .CMP) catch unreachable;
	token_map.put("jmp", .JMP) catch unreachable;
	token_map.put("jlt", .JLT) catch unreachable;
	token_map.put("jgt", .JGT) catch unreachable;
	token_map.put("jle", .JLE) catch unreachable;
	token_map.put("jge", .JGE) catch unreachable;
	token_map.put("jz", .JZ) catch unreachable;
	token_map.put("jnz", .JNZ) catch unreachable;
	token_map.put("jeq", .JEQ) catch unreachable;
	token_map.put("jne", .JNE) catch unreachable;
	token_map.put("int", .INT) catch unreachable;
	token_map.put("ip", .IP) catch unreachable;
	token_map.put("r0", .R0) catch unreachable;
	token_map.put("r1", .R1) catch unreachable;
	token_map.put("r2", .R2) catch unreachable;
	token_map.put("r3", .R3) catch unreachable;
	var tokens = Buffer(Token).init(mem.*);
	while (i<text.len){
		var escape = false;
		const c = text[i];
		if (c == '\\'){
			escape = true;
		}
		var tag:TOKEN = blk:{
			switch (c) {
				' ' => {break :blk .SPACE;},
				'\t' => {break :blk .TAB;},
				'\n' => {break :blk .NEW_LINE;},
				'{' => {break :blk .OPEN_BRACE;},
				'}' => {break :blk .CLOSE_BRACE;},
				'[' => {break :blk .OPEN_BRACK;},
				']' => {break :blk .CLOSE_BRACK;},
				'|' => {break :blk .ALTERNATE;},
				'?' => {break :blk .OPTIONAL;},
				'$' => {break :blk .LINE_START;},
				'^' => {break :blk .LINE_END;},
				'@' => {break :blk .UNIQUE;},
				';' => {break :blk .HOIST;},
				':' => {break :blk .IS_OF;},
				'+' => {break :blk .ARGUMENT;},
				'-' => {break :blk .EXCLUSION;},
				else => {break :blk .IDENTIFIER;}
			}
			break :blk .IDENTIFIER;
		};
		if (tag != .IDENTIFIER){
			if (escape){
				tag = .IDENTIFIER;
			}
			tokens.append(Token{.tag=tag, .text=text[i..i+1]})
				catch unreachable;
			i += 1;
			continue;
		}
		var size: u64 = 1;
		const keyword = blk:{
			if (std.ascii.isAlphanumeric(c)){
				while (i+size < text.len and std.ascii.isAlphanumeric(text[i+size])){
					size += 1;
				}
				break :blk text[i..i+size];
			}
			while (i+size < text.len or (!std.ascii.isWhitespace(text[i+size]) and !std.ascii.isAlphanumeric(text[i+size]))){
				size += 1;
			}
			break :blk text[i..i+size];
		};
		if (token_map.get(keyword)) |map_tag| {
			tag = map_tag;
			if (escape){
				tag = .IDENTIFIER;
			}
		}
		tokens.append(Token{.tag=.IDENTIFIER, .text=keyword})
			catch unreachable;
		i += size;
	}
	return tokens;
}

pub fn show_tokens(tokens: Buffer(Token)) void {
	for (tokens.items) |*token| {
		std.debug.print("{}:{s} ", .{token.tag, token.text});
	}
	std.debug.print("\n", .{});
}
