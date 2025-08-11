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
	var main_aux = std.heap.ArenaAllocator.init(allocator);
	var main_txt = std.heap.ArenaAllocator.init(allocator);
	defer main_mem.deinit();
	const mem = main_mem.allocator();
	const txt = main_txt.allocator();
	const aux = main_aux.allocator();
	var tokens = tokenize(&mem, contents);
	show_tokens(tokens);
	var text = Buffer(Token).init(txt);
	var auxil = Buffer(Token).init(aux);
	var program = ProgramText{
		.text=&text,
		.binds=Buffer(Bind).init(mem)
	};
	var token_stream = &tokens;
	var done = false;
	while (!done){
		program.text=&text;
		text.clearRetainingCapacity();
		done = parse(&mem, token_stream, &program) catch {
			//TODO error report
			return;
		};
		token_stream = &text;
		if (done){
			break;
		}
		program.text=&auxil;
		auxil.clearRetainingCapacity();
		done = parse(&mem, token_stream, &program) catch {
			//TODO error report
			return;
		};
		token_stream = &auxil;
	}
}

const ParseError = error {
	PrematureEnd,
	UnexpectedToken,
	UnexpectedEOF
};

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
		inclusion, exclusion, optional
	},
	name: Token,
	pattern: Pattern
};

const Pattern = union(enum) {
	token,
	keyword: Token,
	alternate: Buffer(Buffer(*Arg)),
	group: struct {
		open: *Arg,
		close: *Arg
	},
	variadic: struct {
		members: Buffer(*Arg),
		separator: ?*Arg
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
	text: Buffer(Token)
};

const ProgramText = struct {
	text: *Buffer(Token),
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

pub fn parse(mem: *const std.mem.Allocator, tokens: *Buffer(Token), program: *ProgramText) !bool {
	var done = true;
	var token_index:u64 = 0;
	while (token_index < tokens.items.len){
		const token = &tokens.items[token_index];
		if (token.tag != .BIND and
			token.tag != .BIND_COMP and
			token.tag != .BIND_PATTERN){
			program.text.append(token.*)
				catch unreachable;
			token_index += 1;
			continue;
		}
		done = false;
		program.binds.append(try parse_bind(mem, tokens.items[token_index..], &token_index))
			catch unreachable;
	}
	return done;
}

pub fn parse_bind(mem: *const std.mem.Allocator, tokens: []Token, token_index: *u64) !Bind {
	std.debug.assert(
		tokens[0].tag == .BIND or
		tokens[0].tag == .BIND_COMP or
		tokens[0].tag == .BIND_PATTERN
	);
	var bind = Bind{
		.tag = .rewrite,
		.precedence=0,
		.args=Buffer(Arg).init(mem.*),
		.text=Buffer(Token).init(mem.*)
	};
	if (tokens[0].tag == .BIND_COMP){
		bind.tag = .compile;
	}
	else if (tokens[0].tag == .BIND_PATTERN){
		bind.tag = .pattern;
	}
	//TODO parse precedence
	var i:u64 = 2;
	while (i < tokens.len){
		const token = &tokens[i];
		if (token.tag == .OPEN_BRACE){
			break;
		}
		const old = i;
		bind.args.append(try parse_arg(mem, tokens[i..], &i))
			catch unreachable;
		token_index.* += old-i;
	}
	std.debug.assert(tokens[i].tag == .OPEN_BRACE);
	var depth: u64 = 0;
	while (i < tokens.len){
		if (tokens[i].tag == .CLOSE_BRACE){
			if (depth == 0){
				break;
			}
			depth -= 1;
		}
		else if (tokens[i].tag == .OPEN_BRACE){
			depth += 1;
		}
		bind.text.append(tokens[i])
			catch unreachable;
		token_index.* += 1;
		i += 1;
	}
	if (tokens[i].tag != .CLOSE_BRACE){
		return ParseError.PrematureEnd;
	}
	return bind;
}

pub fn parse_arg(mem: *const std.mem.Allocator, tokens: []Token, token_index: *u64) ParseError!Arg {
	var i:u64 = 0;
	if (tokens[i].tag == .IDENTIFIER){
		token_index.* += 1;
		return Arg {
			.tag = .inclusion,
			.name=tokens[i],
			.pattern=Pattern{
				.keyword=tokens[i]
			}
		};
	}
	var arg = Arg{
		.tag = .inclusion,
		.name=undefined,
		.pattern=undefined
	};
	if (tokens[i].tag == .EXCLUSION){
		arg.tag = .exclusion;
	}
	else if (tokens[i].tag == .OPTIONAL){
		arg.tag = .optional; 
	}
	else if (tokens[i].tag != .ARGUMENT){
		return ParseError.UnexpectedToken;
	}
	i += 1;
	token_index.* += 1;
	if (i == tokens.len){
		return ParseError.UnexpectedEOF;
	}
	if (tokens[i].tag != .IDENTIFIER){
		return ParseError.UnexpectedToken;
	}
	arg.name = tokens[i];
	i += 1;
	token_index.* += 1;
	if (i == tokens.len){
		return ParseError.UnexpectedEOF;
	}
	if (tokens[i].tag != .IS_OF){
		token_index.* += 1;
		arg.pattern = Pattern.token;
	}
	i += 1;
	token_index.* += 1;
	if (i == tokens.len){
		return ParseError.UnexpectedEOF;
	}
	const old = i;
	arg.pattern = try parse_pattern(mem, tokens[i..], &i);
	token_index.* += old-i;
	return arg;
}

pub fn parse_pattern(mem: *const std.mem.Allocator, tokens: []Token, token_index: *u64) ParseError!Pattern {
	var i: u64 = 0;
	if (tokens[i].tag == .OPEN_BRACK){
		var pattern = Pattern{
			.alternate=Buffer(Buffer(*Arg)).init(mem.*)
		};
		token_index.* += 1;
		i += 1;
		if (i == tokens.len){
			return ParseError.UnexpectedEOF;
		}
		while (i < tokens.len){
			if (tokens[i].tag == .CLOSE_BRACK){
				break;
			}
			var list = Buffer(*Arg).init(mem.*);
			while (i < tokens.len){
				const old = i;
				const loc = mem.create(Arg)
					catch unreachable;
				loc.* = try parse_arg(mem, tokens[i..], &i);
				token_index.* += old-i;
				list.append(loc)
					catch unreachable;
				if (tokens[i].tag == .ALTERNATE){
					break;
				}
			}
			pattern.alternate.append(list)
				catch unreachable;
		}
		return pattern;
	}
	if (tokens[i].tag == .OPEN_BRACE){
		var pattern = Pattern{
			.variadic=.{
				.members = Buffer(*Arg).init(mem.*),
				.separator = null
			}
		};
		while (i < tokens.len){
			const old = i;
			const loc = mem.create(Arg)
					catch unreachable;
			loc.* = try parse_arg(mem, tokens[i..], &i);
			token_index.* += old-1;
			pattern.variadic.members.append(loc)
				catch unreachable;
			if (tokens[i].tag == .CLOSE_BRACE){
				pattern.variadic.separator = pattern.variadic.members.pop();
				break;
			}
		}
		std.debug.assert(pattern.variadic.separator != null);
		return pattern;
	}
	const open_loc = mem.create(Arg)
		catch unreachable;
	var old = i;
	open_loc.* = try parse_arg(mem, tokens[i..], &i);
	token_index.* += old-i;
	if (tokens[i].tag != .ELIPSES){
		return ParseError.UnexpectedToken;
	}
	const close_loc = mem.create(Arg)
		catch unreachable;
	old = i;
	close_loc.* = try parse_arg(mem, tokens[i..], &i);
	token_index.* += old-i;
	return Pattern{
		.group = .{
			.open=open_loc,
			.close=close_loc
		}
	};
}
