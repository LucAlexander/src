const std = @import("std");
const Buffer = std.ArrayList;

const debug = true;

const uid: []const u8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

var iden_hashes = std.StringHashMap(u64).init(std.heap.page_allocator);
var current_iden: u64 = 0;

var persistent = std.StringHashMap(u64).init(std.heap.page_allocator);
var comp_persistent = std.StringHashMap(u64).init(std.heap.page_allocator);
var comp_section = false;

const mem_size = 0x1000;
const frame_buffer = 800*600;
const register_section = 8*5;

const VM = struct {
	mem: [mem_size+frame_buffer+register_section]u8,
	r0: u64,
	r1: u64,
	r2: u64,
	r3: u64,
	sr: u64,
	
	pub fn init() VM {
		return VM{
			.mem=undefined,
			.r0=mem_size,
			.r1=mem_size+1*8,
			.r2=mem_size+2*8,
			.r3=mem_size+3*8,
			.sr=mem_size+4*8
		};
	}
};

var vm: VM = VM.init();

pub fn main() !void {
	const allocator = std.heap.page_allocator;
	var infile = try std.fs.cwd().openFile("simple.src", .{});
	defer infile.close();
	const stat = try infile.stat();
	const contents = try infile.readToEndAlloc(allocator, stat.size+1);
	defer allocator.free(contents);
	var main_mem = std.heap.ArenaAllocator.init(allocator);
	defer main_mem.deinit();
	const mem = main_mem.allocator();
	const tokens = tokenize(&mem, contents);
	show_tokens(tokens);
	if (debug){
		std.debug.print("initial------------------------------\n", .{});
	}
	var binds = Buffer(Bind).init(mem);
	_ = metaprogram(&tokens, &binds, &mem, true);
}

pub fn metaprogram(tokens: *const Buffer(Token), binds: *Buffer(Bind), mem: *const std.mem.Allocator, run: bool) ?Buffer(Token) {
	const allocator = std.heap.page_allocator;
	var main_aux = std.heap.ArenaAllocator.init(allocator);
	var main_txt = std.heap.ArenaAllocator.init(allocator);
	defer main_aux.deinit();
	defer main_txt.deinit();
	const txt = main_txt.allocator();
	const aux = main_aux.allocator();
	var text = Buffer(Token).init(txt);
	var auxil = Buffer(Token).init(aux);
	var program = ProgramText{
		.text=&text,
		.binds=binds
	};
	var token_stream = tokens;
	var token_index: u64 = 0;
	program.text=&text;
	var concatenated = true;
	while (concatenated){
		var redo = true;
		while (redo){
			var done = false;
			while (!done){
				program.text.clearRetainingCapacity();
				token_index = 0;
				done = parse(mem, token_stream, &program, &token_index) catch |err| {
					std.debug.print("Parse Error {}\n", .{err});
					report_error(token_stream, token_index);
					return null;
				};
				show_program(program);
				if (debug){
					std.debug.print("parsed--------------------------\n", .{});
				}
				if (program.text == &text){
					token_stream = apply_binds(mem, &text, &auxil, &program, &done) catch |err| {
						std.debug.print("Parse Error {}\n", .{err});
						return null;
					};
				}
				else {
					token_stream = apply_binds(mem, &auxil, &text, &program, &done) catch |err| {
						std.debug.print("Parse Error {}\n", .{err});
						return null;
					};
				}
				show_tokens(token_stream.*);
				if (debug){
					std.debug.print("applied binds-------------------\n", .{});
				}
			}
			redo = fill_hoist(mem, program.text, token_stream, program.binds) catch |err| {
				std.debug.print("Hoist Error {}\n", .{err});
				return null;
			};
			show_tokens(program.text.*);
			if (debug){
				std.debug.print("hoisted--------------------------\n", .{});
			}
			if (program.text == &auxil){
				program.text = &text;
				token_stream = &auxil;
			}
			else{
				program.text = &auxil;
				token_stream = &text;
			}
			if (redo == false){
				break;
			}
		}
		concatenated = concat_pass(mem, program.text, token_stream) catch |err| {
			std.debug.print("Error while concatenating {}\n", .{err});
			return null;
		};
		if (program.text == &auxil){
			program.text = &text;
			token_stream = &auxil;
		}
		else{
			program.text = &auxil;
			token_stream = &text;
		}
		if (concatenated == false){
			break;
		}

	}
	if (run){
		var index:u64 = 0;
		const instructions = parse_bytecode(mem, token_stream, &index, false) catch |err| {
			std.debug.print("Bytecode Parse Error {}\n", .{err});
			return null;
		};
		show_instructions(instructions);
		if (debug){
			std.debug.print("parsed bytecode--------------------\n", .{});
		}
		vm = VM.init();
		interpret(instructions) catch |err| {
			std.debug.print("Runtime Error {}\n", .{err});
			return null;
		};
	}
	var stream = Buffer(Token).init(mem.*);
	stream.appendSlice(token_stream.items) catch unreachable;
	return stream;
}

const ParseError = error {
	PrematureEnd,
	UnexpectedToken,
	UnexpectedEOF,
	AlternateUnmatchable,
	ConstMatched,
	BrokenComptime,
	NoHoist,
	NoArgs
};

const TOKEN = enum {
	BIND, COMP_START, COMP_END,
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
	LIT,
	EQUAL,
	ADD, SUB, MUL, DIV, CMP,
	JMP,
	JLT, JGT, JLE, JGE,
	JZ, JNZ, JEQ, JNE,
	INT,
	IP, R0, R1, R2, R3,
	SPACE, NEW_LINE, TAB, CONCAT,
	LINE_END, WHITESPACE
};

const Token = struct {
	text: []u8,
	tag: TOKEN,
	hoist_data: ?Buffer(AppliedBind)
};

const Arg = struct {
	tag: enum {
		unique, inclusion, exclusion, optional
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
	precedence: u8,
	args: Buffer(Arg),
	hoist: Buffer(Token),
	hoist_token: ?Arg,
	text: Buffer(Token)
};

//TODO memory optimization
const ArgTree = struct {
	nodes: Buffer(*ArgTree),
	arg: Arg,
	alternate: u64,
	expansion: ?[]Token,
	expansion_len: u64,
	
	pub fn init(mem: *const std.mem.Allocator, arg: Arg, exp: ?[]Token) *ArgTree {
		if (exp) |e| {
			const tree = ArgTree {
				.arg=arg,
				.expansion=e,
				.alternate=0,
				.nodes=Buffer(*ArgTree).init(mem.*),
				.expansion_len = e.len
			};
			const loc = mem.create(ArgTree) catch unreachable;
			loc.* = tree;
			return loc;
		}
		const tree = ArgTree {
			.arg=arg,
			.expansion=exp,
			.alternate=0,
			.nodes=Buffer(*ArgTree).init(mem.*),
			.expansion_len = 0
		};
		const loc = mem.create(ArgTree) catch unreachable;
		loc.* = tree;
		return loc;
	}
};

const AppliedBind = struct {
	bind: u64,
	expansions: Buffer(*ArgTree),
	uniques: std.StringHashMap([]u8),
	start_index: u64,
	end_index: u64
};

const ProgramText = struct {
	text: *Buffer(Token),
	binds: *Buffer(Bind)
};

pub fn tokenize(mem: *const std.mem.Allocator, text: []u8) Buffer(Token) {
	var i: u64 = 0;
	var token_map = std.StringHashMap(TOKEN).init(mem.*);
	token_map.put("bind", .BIND) catch unreachable;
	token_map.put("...", .ELIPSES) catch unreachable;
	token_map.put(";;;", .HOIST) catch unreachable;
	var tokens = Buffer(Token).init(mem.*);
	while (i<text.len){
		var escape = false;
		var c = text[i];
		if (c == '\\'){
			escape = true;
			i += 1;
			if (i == text.len){
				break;
			}
			c = text[i];
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
				'$' => {break :blk .LINE_END;},
				'#' => {break :blk .CONCAT;},
				'%' => {break :blk .WHITESPACE;},
				'@' => {break :blk .UNIQUE;},
				'!' => {break :blk .LIT;},
				':' => {break :blk .IS_OF;},
				'+' => {break :blk .ARGUMENT;},
				'-' => {break :blk .EXCLUSION;},
				'=' => {break :blk .EQUAL;},
				else => {break :blk .IDENTIFIER;}
			}
			break :blk .IDENTIFIER;
		};
		if (tag != .IDENTIFIER){
			if (escape){
				tag = .IDENTIFIER;
			}
			tokens.append(Token{.tag=tag, .text=text[i..i+1], .hoist_data=null})
				catch unreachable;
			i += 1;
			continue;
		}
		var size: u64 = 1;
		const keyword = blk:{
			if (std.ascii.isAlphanumeric(c) or c == '_'){
				while (i+size < text.len and (text[i+size] == '_' or std.ascii.isAlphanumeric(text[i+size]))){
					size += 1;
				}
				break :blk text[i..i+size];
			}
			while (i+size < text.len and (!std.ascii.isWhitespace(text[i+size])
				                     and !std.ascii.isAlphanumeric(text[i+size])
									 and text[i+size] != '\\')){
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
		tokens.append(Token{.tag=tag, .text=keyword, .hoist_data=null})
			catch unreachable;
		i += size;
	}
	return tokens;
}

pub fn retokenize(mem: *const std.mem.Allocator, tokens: *const Buffer(Token)) ParseError!void {
	var token_map = std.StringHashMap(TOKEN).init(mem.*);
	token_map.put("comp", .COMP_START) catch unreachable;
	token_map.put("run", .COMP_END) catch unreachable;
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
	for (tokens.items) |*token| {
		if (token_map.get(token.text)) |tag| {
			token.tag = tag;
		}
		if (token.hoist_data) |_| {
			std.debug.print("Left over hoist at {s} never found anchor\n", .{token.text});
			return ParseError.NoHoist;
		}
	}
}

pub fn show_tokens(tokens: Buffer(Token)) void {
	if (!debug){
		return;
	}
	for (tokens.items) |*token| {
		if (token.hoist_data) |_| {
			std.debug.print("* ", .{});
		}
		std.debug.print("{} {s}\n", .{token.tag, token.text});
	}
	std.debug.print("\n", .{});
}

pub fn parse(mem: *const std.mem.Allocator, tokens: *const Buffer(Token), program: *ProgramText, token_index: *u64) !bool {
	var done = true;
	while (token_index.* < tokens.items.len){
		const token = &tokens.items[token_index.*];
		if (token.tag != .BIND){
			program.text.append(token.*)
				catch unreachable;
			token_index.* += 1;
			continue;
		}
		if (try parse_bind(mem, tokens.items, token_index)) |bind| {
			done = false;
			program.binds.append(bind)
				catch unreachable;
			while (token_index.* < tokens.items.len){
				const copy = tokens.items[token_index.*];
				program.text.append(copy)
					catch unreachable;
				token_index.* += 1;
			}
			return done;
		}
		program.text.append(token.*)
			catch unreachable;
		token_index.* += 1;
	}
	return done;
}

pub fn parse_bind(mem: *const std.mem.Allocator, tokens: []Token, token_index: *u64) !?Bind {
	const token_save = token_index.*;
	std.debug.assert(tokens[token_index.*].tag == .BIND);
	var bind = Bind{
		.precedence=0,
		.args=Buffer(Arg).init(mem.*),
		.hoist=Buffer(Token).init(mem.*),
		.hoist_token=null,
		.text=Buffer(Token).init(mem.*)
	};
	token_index.* += 1;
	try skip_whitespace(tokens, token_index);
	const precedence = tokens[token_index.*];
	if (precedence.tag != .IDENTIFIER){
		std.debug.print("Expected precedence level\n", .{});
		return ParseError.UnexpectedToken;
	}
	bind.precedence = precedence.text[0];
	token_index.* += 1;
	while (token_index.* < tokens.len){
		try skip_whitespace(tokens, token_index);
		const token = &tokens[token_index.*];
		if (token.tag == .OPEN_BRACE or token.tag == .EQUAL){
			break;
		}
		bind.args.append(try parse_arg(mem, tokens, token_index))
			catch unreachable;
	}
	if (bind.args.items.len == 0){
		std.debug.print("No args provided to bind\n", .{});
		return ParseError.NoArgs;
	}
	try skip_whitespace(tokens, token_index);
	const eq = tokens[token_index.*];
	if (eq.tag == .EQUAL){
		token_index.* = token_save;
		return null;
	}
	else if (eq.tag != .OPEN_BRACE){
		std.debug.print("Expected open brace to define bind replacement segment, found {s}\n", .{eq.text});
		return ParseError.UnexpectedToken;
	}
	token_index.* += 1;
	var depth: u64 = 0;
	while (token_index.* < tokens.len){
		if (tokens[token_index.*].tag == .CLOSE_BRACE){
			if (depth == 0){
				break;
			}
			depth -= 1;
		}
		else if (tokens[token_index.*].tag == .OPEN_BRACE){
			depth += 1;
		}
		bind.text.append(tokens[token_index.*])
			catch unreachable;
		token_index.* += 1;
		try skip_whitespace(tokens, token_index);
	}
	try skip_whitespace(tokens, token_index);
	if (tokens[token_index.*].tag != .CLOSE_BRACE){
		std.debug.print("Program ended in the middle of a bind expansion defintion, expected closing brace\n", .{});
		return ParseError.PrematureEnd;
	}
	token_index.* += 1;
	try split_hoist(mem, &bind);
	return bind;
}

pub fn split_hoist(mem: *const std.mem.Allocator, bind: *Bind) ParseError!void {
	var token_index = bind.text.items.len;
	while (token_index > 0){
		const i = token_index-1;
		const tok = bind.text.items[i];
		token_index -= 1;
		if (tok.tag == .HOIST){
			var index: u64 = 0;
			while (index < i){
				bind.hoist.append(bind.text.items[index])
					catch unreachable;
				index += 1;
			}
			index += 1;
			if (index >= bind.text.items.len){
				std.debug.print("Expected token to hoist to\n", .{});
				return ParseError.UnexpectedEOF;
			}
			bind.hoist_token = try parse_arg(mem, bind.text.items, &index);
			var offset: u64 = 0;
			while (index < bind.text.items.len) {
				bind.text.items[offset] = bind.text.items[index];
				index += 1;
				offset += 1;
			}
			bind.text.items.len = offset;
			return;
		}
	}
}

pub fn skip_whitespace(tokens: []Token, token_index: *u64) ParseError!void {
	while (token_index.* < tokens.len){
		if (tokens[token_index.*].tag == .SPACE){
			token_index.* += 1;
			continue;
		}
		if (tokens[token_index.*].tag == .TAB){
			token_index.* += 1;
			continue;
		}
		if (tokens[token_index.*].tag == .NEW_LINE){
			token_index.* += 1;
			continue;
		}
		return;
	}
	token_index.*-=1;
	std.debug.print("Encountered end of file in whitespace skip\n", .{});
	return ParseError.UnexpectedEOF;
}

pub fn parse_arg(mem: *const std.mem.Allocator, tokens: []Token, token_index: *u64) ParseError!Arg {
	if (token_index.* >= tokens.len){
		std.debug.print("Expected argument or expansion but file ended\n", .{});
		return ParseError.UnexpectedEOF;
	}
	if (tokens[token_index.*].tag == .UNIQUE){
		token_index.* += 1;
		if (tokens[token_index.*].tag != .IDENTIFIER){
			std.debug.print("Expected identifier for unique name, found {s}\n", .{tokens[token_index.*].text});
			return ParseError.UnexpectedToken;
		}
		const arg = Arg {
			.tag = .unique,
			.name = tokens[token_index.*],
			.pattern=Pattern{
				.keyword=tokens[token_index.*]
			}
		};
		var inner = Buffer(*Arg).init(mem.*);
		const atloc = mem.create(Arg) catch unreachable;
		const idenloc = mem.create(Arg) catch unreachable;
		atloc.* = Arg{
			.tag=.inclusion,
			.name=tokens[token_index.*-1],
			.pattern=Pattern{
				.keyword=tokens[token_index.*-1]
			}
		};
		idenloc.* = Arg{
			.tag=.inclusion,
			.name=tokens[token_index.*],
			.pattern=Pattern{
				.keyword=tokens[token_index.*]
			}
		};
		inner.append(atloc)
			catch unreachable;
		inner.append(idenloc)
			catch unreachable;
		token_index.* += 1;
		return arg;
	}
	if (tokens[token_index.*].tag == .IDENTIFIER or
		tokens[token_index.*].tag == .WHITESPACE or
		tokens[token_index.*].tag == .CONCAT or
		tokens[token_index.*].tag == .LINE_END){
		const arg = Arg {
			.tag = .inclusion,
			.name=tokens[token_index.*],
			.pattern=Pattern{
				.keyword=tokens[token_index.*]
			}
		};
		token_index.* += 1;
		return arg;
	}
	var arg = Arg{
		.tag = .inclusion,
		.name=undefined,
		.pattern=undefined
	};
	if (tokens[token_index.*].tag == .EXCLUSION){
		arg.tag = .exclusion;
	}
	else if (tokens[token_index.*].tag == .OPTIONAL){
		arg.tag = .optional; 
	}
	else if (tokens[token_index.*].tag != .ARGUMENT){
		const nonstandard = Arg {
			.tag = .inclusion,
			.name=tokens[token_index.*],
			.pattern=Pattern{
				.keyword=tokens[token_index.*]
			}
		};
		token_index.* += 1;
		return nonstandard;
	}
	token_index.* += 1;
	if (token_index.* == tokens.len){
		std.debug.print("Found end of file in the middle of a pattern definition\n", .{});
		token_index.*-=1;
		return ParseError.UnexpectedEOF;
	}
	if (tokens[token_index.*].tag != .IDENTIFIER){
		std.debug.print("Expected identifier for argument name, found {s}\n", .{tokens[token_index.*].text});
		return ParseError.UnexpectedToken;
	}
	arg.name = tokens[token_index.*];
	token_index.* += 1;
	if (token_index.* == tokens.len){
		std.debug.print("Found end of file in the middle of a pattern definition, expected either : pattern scheme or expansion\n", .{});
		token_index.*-=1;
		return ParseError.UnexpectedEOF;
	}
	if (tokens[token_index.*].tag != .IS_OF){
		arg.pattern = Pattern.token;
		return arg;
	}
	token_index.* += 1;
	if (token_index.* == tokens.len){
		std.debug.print("Found end of file in the middle of a pattern definition, expected pattern scheme following :\n", .{});
		token_index.*-=1;
		return ParseError.UnexpectedEOF;
	}
	arg.pattern = try parse_pattern(mem, tokens, token_index);
	return arg;
}

pub fn parse_pattern(mem: *const std.mem.Allocator, tokens: []Token, token_index: *u64) ParseError!Pattern {
	if (tokens[token_index.*].tag == .OPEN_BRACK){
		var pattern = Pattern{
			.alternate=Buffer(Buffer(*Arg)).init(mem.*)
		};
		token_index.* += 1;
		try skip_whitespace(tokens, token_index);
		if (token_index.* == tokens.len){
			std.debug.print("Found end of file in the middle of a pattern definition\n", .{});
			token_index.*-=1;
			return ParseError.UnexpectedEOF;
		}
		blk: while (token_index.* < tokens.len){
			if (tokens[token_index.*].tag == .CLOSE_BRACK){
				token_index.* += 1;
				try skip_whitespace(tokens, token_index);
				break;
			}
			var list = Buffer(*Arg).init(mem.*);
			while (token_index.* < tokens.len){
				const loc = mem.create(Arg)
					catch unreachable;
				loc.* = try parse_arg(mem, tokens, token_index);
				list.append(loc)
					catch unreachable;
				try skip_whitespace(tokens, token_index);
				if (tokens[token_index.*].tag == .ALTERNATE){
					token_index.* += 1;
					break;
				}
				if (tokens[token_index.*].tag == .CLOSE_BRACK){
					token_index.* += 1;
					pattern.alternate.append(list)
						catch unreachable;
					break :blk;
				}
			}
			pattern.alternate.append(list)
				catch unreachable;
		}
		return pattern;
	}
	if (tokens[token_index.*].tag == .OPEN_BRACE){
		token_index.* += 1;
		try skip_whitespace(tokens, token_index);
		var pattern = Pattern{
			.variadic=.{
				.members = Buffer(*Arg).init(mem.*),
				.separator = null
			}
		};
		while (token_index.* < tokens.len){
			const loc = mem.create(Arg)
					catch unreachable;
			loc.* = try parse_arg(mem, tokens, token_index);
			pattern.variadic.members.append(loc)
				catch unreachable;
			try skip_whitespace(tokens, token_index);
			if (tokens[token_index.*].tag == .CLOSE_BRACE){
				pattern.variadic.separator = pattern.variadic.members.pop();
				token_index.* += 1;
				try skip_whitespace(tokens, token_index);
				break;
			}
		}
		std.debug.assert(pattern.variadic.separator != null);
		return pattern;
	}
	const open_loc = mem.create(Arg)
		catch unreachable;
	open_loc.* = try parse_arg(mem, tokens, token_index);
	try skip_whitespace(tokens, token_index);
	if (tokens[token_index.*].tag != .ELIPSES){
		std.debug.print("Expected elipses ... for grouping expression, found {s}\n", .{tokens[token_index.*].text});
		return ParseError.UnexpectedToken;
	}
	token_index.* += 1;
	try skip_whitespace(tokens, token_index);
	const close_loc = mem.create(Arg)
		catch unreachable;
	close_loc.* = try parse_arg(mem, tokens, token_index);
	return Pattern{
		.group = .{
			.open=open_loc,
			.close=close_loc
		}
	};
}

pub fn report_error(token_stream: *const Buffer(Token), token_index: u64) void{
	var i = token_index;
	while (i > 0){
		if (token_stream.items[i].tag == .NEW_LINE){
			i += 1;
			break;
		}
		i = i - 1;
	}
	var k = i;
	while (i < token_stream.items.len){
		std.debug.print("{s}", .{token_stream.items[i].text});
		if (token_stream.items[i].tag == .NEW_LINE){
			break;
		}
		i = i + 1;
	}
	while (k < token_index){
		k = k + 1;
		const token = token_stream.items[k];
		for (token.text) |c| {
			if (c == '\t'){
				std.debug.print("\t", .{});
				continue;
			}
			std.debug.print(" ", .{});
		}
	}
	std.debug.print(" ^\n", .{});
}

pub fn show_program(program: ProgramText) void {
	if (!debug){
		return;
	}
	show_tokens(program.text.*);
	std.debug.print("end text -----------\n", .{});
	for (program.binds.items) |bind| {
		std.debug.print("precedence {}\nargs:\n", .{bind.precedence});
		for (bind.args.items) |arg| {
			show_arg(arg);
			std.debug.print("\n", .{});
		}
		std.debug.print("expansion:\n", .{});
		if (bind.hoist_token) |_| {
			show_tokens(bind.hoist);
			std.debug.print(";\n", .{});
		}
		show_tokens(bind.text);
	}
	std.debug.print("end binds ----------\n", .{});
}

pub fn show_arg(arg: Arg) void {
	if (!debug){
		return;
	}
	std.debug.print("{} {s}:", .{arg.tag, arg.name.text});
	switch (arg.pattern){
		.token => {},
		.keyword => {
			std.debug.print("{s}", .{arg.pattern.keyword.text});
		},
		.alternate => {
			std.debug.print("[\n", .{});
			for (arg.pattern.alternate.items) |*list| {
				std.debug.print("| ", .{});
				for (list.items) |inner| {
					show_arg(inner.*);
					std.debug.print("\n", .{});
				}
			}
			std.debug.print("]", .{});
		},
		.group => {
			show_arg(arg.pattern.group.open.*);
			std.debug.print("...", .{});
			show_arg(arg.pattern.group.close.*);
		},
		.variadic => {
			std.debug.print("VARIADIC_OPEN\n", .{});
			for (arg.pattern.variadic.members.items) |positional| {
				show_arg(positional.*);
				std.debug.print("\n", .{});
			}
			if (arg.pattern.variadic.separator) |real|{
				show_arg(real.*);
			}
			else{
				std.debug.assert(false);
			}
			std.debug.print("VARIADIC_CLOSE", .{});
		}
	}
}

const PatternError = error {
	MissingKeyword,
	ExhaustedAlternate,
	ExclusionPresent,
	UnexpectedEOF
};

pub fn apply_rule(mem: *const std.mem.Allocator, uniques: *std.StringHashMap([]u8), rule: *Arg, tokens: []Token, token_index: u64, var_depth: u64) PatternError!?*ArgTree{
	switch (rule.tag){
		.unique => {
			std.debug.assert(rule.pattern == Pattern.keyword);
			if (uniques.get(rule.name.text) == null){
				uniques.put(rule.name.text, new_uid(mem))
					catch unreachable;
			}
			return null;
		},
		.inclusion => {
			return apply_pattern(mem, rule.*, &rule.pattern, tokens, token_index, var_depth, uniques);
		},
		.exclusion => {
			_ = apply_pattern(mem, rule.*, &rule.pattern, tokens, token_index, var_depth, uniques) catch {
				return null;
			};
			return PatternError.ExclusionPresent;
		},
		.optional => {
			return apply_pattern(mem, rule.*, &rule.pattern, tokens, token_index, var_depth, uniques) catch {
				return null;
			};
		}
	}
	unreachable;
}

pub fn apply_pattern(mem: *const std.mem.Allocator, name: Arg, pattern: *Pattern, tokens: []Token, token_index: u64, var_depth: u64, uniques: *std.StringHashMap([]u8)) PatternError!*ArgTree {
	switch (pattern.*){
		.token => {
			const new_index = apply_whitespace(token_index, tokens);
			if (new_index >= tokens.len){
				return PatternError.UnexpectedEOF; 
			}
			return ArgTree.init(mem, name, tokens[token_index..new_index+1]);
		},
		.keyword => {
			if (pattern.keyword.tag == .LINE_END){
				if (tokens[token_index].tag == .NEW_LINE){
					return ArgTree.init(mem, name, tokens[token_index..token_index+1]);
				}
				return PatternError.MissingKeyword;
			}
			if (pattern.keyword.tag == .WHITESPACE){
				if (tokens[token_index].tag == .NEW_LINE or
					tokens[token_index].tag == .SPACE or
					tokens[token_index].tag == .TAB){
					return ArgTree.init(mem, name, tokens[token_index..token_index+1]);
				}
				return PatternError.MissingKeyword;
			}
			const new_index = apply_whitespace(token_index, tokens);
			if (new_index >= tokens.len){
				return PatternError.UnexpectedEOF; 
			}
			if (token_equal(&tokens[new_index], &pattern.keyword)){
				return ArgTree.init(mem, name, tokens[token_index..new_index+1]);
			}
			return PatternError.MissingKeyword;
		},
		.alternate => |*alternate| {
			var list = Buffer(*ArgTree).init(mem.*);
			blk: for (alternate.items, 0..) |*seqlist, alt| {
				var temp_index = token_index;
				for (seqlist.items) |arg| {
					const sequence = apply_rule(mem, uniques, arg, tokens, temp_index, var_depth) catch {
						list.clearRetainingCapacity();
						continue :blk;
					};
					if (sequence) |seq| {
						std.debug.assert(seq.expansion != null);
						list.append(seq)
							catch unreachable;
						temp_index += seq.expansion_len;
					}
				}
				const tree = ArgTree.init(mem, name, tokens[token_index..temp_index]);
				tree.nodes = list;
				tree.alternate=alt;
				return tree;
			}
			return PatternError.ExhaustedAlternate;
		},
		.group => {
			var list = Buffer(*ArgTree).init(mem.*);
			const open_sequence = try apply_rule(mem, uniques, pattern.group.open, tokens, token_index, var_depth);
			var temp_index = token_index;
			if (open_sequence) |seq| {
				std.debug.assert(seq.expansion != null);
				list.append(seq)
					catch unreachable;
				temp_index += seq.expansion_len;
			}
			const after_first = temp_index;
			var before_last = temp_index;
			while (temp_index < tokens.len){
				const close_sequence = apply_rule(mem, uniques, pattern.group.close, tokens, temp_index, var_depth) catch {
					temp_index += 1;
					continue;
				};
				if (close_sequence) |close| {
					std.debug.assert(close.expansion != null);
					list.append(close)
						catch unreachable;
					before_last = temp_index;
					temp_index += close.expansion_len;
				}
				break;
			}
			const tree = ArgTree.init(mem, name, tokens[after_first..before_last]);
			tree.expansion_len = temp_index-token_index;
			tree.nodes = list;
			return tree;
		},
		.variadic => {
			std.debug.assert(pattern.variadic.separator != null);
			var temp_index:u64 = token_index;
			var times:u64 = 0;
			var superlist = Buffer(Buffer(*ArgTree)).init(mem.*);
			while (true){
				const save_index = temp_index;
				var sublist = Buffer(*ArgTree).init(mem.*);
				for (pattern.variadic.members.items) |arg| {
					const sequence = apply_rule(mem, uniques, arg, tokens, temp_index, var_depth+1) catch |err| {
						if (times == 0){
							return err;
						}
						superlist.append(sublist)
							catch unreachable;
						const tree = ArgTree.init(mem, name, tokens[token_index..save_index]);
						for (superlist.items) |list| {
							const subtree = ArgTree.init(mem, name, null);
							subtree.nodes = list;
							tree.nodes.append(subtree)
								catch unreachable;
						}
						return tree;
					};
					if (sequence)|seq| {
						std.debug.assert(seq.expansion != null);
						sublist.append(seq)
							catch unreachable;
						temp_index += seq.expansion_len;
					}
				}
				std.debug.assert(pattern.variadic.separator != null);
				const sep_sequence = apply_rule(mem, uniques, pattern.variadic.separator.?, tokens, temp_index, var_depth+1) catch {
					superlist.append(sublist)
						catch unreachable;
					const tree = ArgTree.init(mem, name, tokens[token_index..temp_index]);
					for (superlist.items) |list| {
						const subtree = ArgTree.init(mem, name, null);
						subtree.nodes = list;
						tree.nodes.append(subtree)
							catch unreachable;
					}
					return tree;
				};
				if (sep_sequence) |sep| {
					std.debug.assert(sep.expansion != null);
					sublist.append(sep)
						catch unreachable;
					temp_index += sep.expansion_len;
				}
				superlist.append(sublist)
					catch unreachable;
				times += 1;
			}
		}
	}
	unreachable;
}

pub fn apply_bind(mem: *const std.mem.Allocator, bind: *Bind, bind_index: u64, tokens: []Token, token_index: *u64) ?AppliedBind {
	const save_index = token_index.*;
	var list = Buffer(*ArgTree).init(mem.*);
	var uniques = std.StringHashMap([]u8).init(mem.*);
	for (bind.args.items) |*arg| {
		if (token_index.* >= tokens.len){
			return null;
		}
		const sequence = apply_rule(mem, &uniques, arg, tokens, token_index.*, 0) catch {
			token_index.* = save_index;
			return null;
		};
		if (sequence) |seq| {
			std.debug.assert(seq.expansion != null);
			list.append(seq)
				catch unreachable;
			token_index.* += seq.expansion_len;
		}
	}
	return AppliedBind{
		.bind = bind_index,
		.expansions=list,
		.uniques=uniques,
		.start_index = save_index,
		.end_index = token_index.*
	};
}

pub fn block_binds(mem: *const std.mem.Allocator, program: *ProgramText, precedence: u64) Buffer(AppliedBind) {
	var buffer = Buffer(AppliedBind).init(mem.*);
	var i: u64 = 0;
	while (i < program.text.items.len){
		var found = false;
		var bind_index: u64 = program.binds.items.len;
		while (bind_index > 0){
			const bind = &program.binds.items[bind_index-1];
			bind_index -= 1;
			if (bind.precedence != precedence){
				continue;
			}
			if (apply_bind(mem, bind, bind_index, program.text.items, &i)) |applied| {
				found = true;
				buffer.append(applied)
					catch unreachable;
			}
		}
		if (!found){
			i += 1;
		}
	}
	return buffer;
}

pub fn aggregate_hoists(mem: *const std.mem.Allocator, input_index: u64, token_index: u64, program:*ProgramText, new: *Buffer(Token)) void {
	var save_index = input_index;
	while (save_index < token_index){
		const candidate = program.text.items[save_index];
		if (candidate.hoist_data) |candidate_hoist| {
			const new_token = &new.items[new.items.len-1];
			if (new_token.hoist_data) |_| {
				for (candidate_hoist.items) |c| {
					new_token.hoist_data.?.append(c)
						catch unreachable;
				}
			}
			else {
				var hd = Buffer(AppliedBind).init(mem.*);
				for (candidate_hoist.items) |c| {
					hd.append(c)
						catch unreachable;
				}
				new_token.hoist_data = hd;
			}
		}
		save_index += 1;
	}

}

pub fn apply_binds(mem: *const std.mem.Allocator, txt: *Buffer(Token), aux: *Buffer(Token), program: *ProgramText, done: *bool) ParseError!*Buffer(Token) {
	var precedence: u64 = blk: {
		var max: u64 = '0';
		for (program.binds.items) |*bind| {
			if (bind.precedence > max){
				max = bind.precedence;
			}
		}
		break :blk max;
	};
	var new = aux;
	while (precedence > '0') {
		var reparse = false;
		const blocks = block_binds(mem, program, precedence);
		if (blocks.items.len == 0){
			precedence -= 1;
			if (precedence <= '0'){
				const stream = program.text;
				program.text = new;
				return stream;
			}
			continue;
		}
		done.* = false;
		new.clearRetainingCapacity();
		var i: u64 = 0;
		var token_index:u64 = 0;
		if (blocks.items.len == 1){
			const current = blocks.items[0];
			while (token_index < current.start_index){
				new.append(program.text.items[token_index])
					catch unreachable;
				token_index += 1;
			}
			const save_index = token_index;
			token_index = current.end_index;
			var stack = Buffer(*ArgTree).init(mem.*);
			_ = try rewrite(mem, program.binds, current, new, 0, false, false, &stack);
			aggregate_hoists(mem, save_index, token_index, program, new);
		}
		else{
			while (i < blocks.items.len-1){
				const current = blocks.items[i];
				const next = blocks.items[i+1];
				while (token_index < current.start_index){
					new.append(program.text.items[token_index])
						catch unreachable;
					token_index += 1;
				}
				const save_index = token_index;
				token_index = current.end_index;
				var adjust = false;
				if (current.end_index > next.start_index and current.end_index < next.end_index){
					adjust = true;
				}
				var stack = Buffer(*ArgTree).init(mem.*);
				_ = try rewrite(mem, program.binds, current, new, 0, false, false, &stack);
				aggregate_hoists(mem, save_index, token_index, program, new);
				if (adjust == true){
					reparse = true;
					while (token_index < program.text.items.len){
						new.append(program.text.items[token_index])
							catch unreachable;
						token_index += 1;
					}
					break;
				}
				i += 1;
			}
			if (reparse == false){
				const current = blocks.items[i];
				while (token_index < current.start_index){
					new.append(program.text.items[token_index])
						catch unreachable;
					token_index += 1;
				}
				const save_index = token_index;
				token_index = current.end_index;
				var stack = Buffer(*ArgTree).init(mem.*);
				_ = try rewrite(mem, program.binds, current, new, 0, false, false, &stack);
				aggregate_hoists(mem, save_index, token_index, program, new);
			}
		}
		while (token_index < program.text.items.len){
			new.append(program.text.items[token_index])
				catch unreachable;
			token_index += 1;
		}
		program.text = new;
		if (new == aux){
			new = txt;
		}
		else {
			new = aux;
		}
		if (reparse == false){
			precedence -= 1;
		}
		if (precedence <= '0'){
			break;
		}
	}
	const stream = program.text;
	program.text = new;
	return stream;
}

pub fn token_equal(a: *Token, b: *Token) bool {
	return std.mem.eql(u8, a.text, b.text);
}

pub fn rewrite(mem: *const std.mem.Allocator, outer_binds: *Buffer(Bind), current: AppliedBind, new: *Buffer(Token), input_index: u64, varnest: bool, altnest: bool, stack: *Buffer(*ArgTree)) ParseError!u64 {
	for (current.expansions.items) |applied| {
		stack.append(applied)
			catch unreachable;
	}
	defer for (current.expansions.items) |_| {
		_ = stack.pop();
	};
	var index: u64 = input_index;
	var nest_depth: u64 = 0;
	var first = true;
	const current_bind = outer_binds.items[current.bind];
	outer: while (index < current_bind.text.items.len) : (index += 1){
		const token = &current_bind.text.items[index];
		if (altnest){
			if (token.tag == .ALTERNATE or token.tag == .CLOSE_BRACK){
				if (nest_depth == 0){
					break :outer;
				}
				if (token.tag == .CLOSE_BRACK){
					nest_depth -= 1;
				}
			}
			else if (token.tag == .OPEN_BRACK){
				nest_depth += 1;
			}
		}
		else if (varnest){
			if (token.tag == .CLOSE_BRACE){
				if (nest_depth == 0){
					break :outer;
				}
				nest_depth -= 1;
			}
			if (token.tag == .OPEN_BRACE){
				nest_depth += 1;
			}
		}
		if (current.uniques.get(token.text)) |id| {
			if (first){
				first = false;
				if (current_bind.hoist_token) |_| {
					var hd = Buffer(AppliedBind).init(mem.*);
					hd.append(current)
						catch unreachable;
					new.append(Token{.tag=.IDENTIFIER, .text=id, .hoist_data=hd})
						catch unreachable;
				}
				else{
					new.append(Token{.tag=.IDENTIFIER, .text=id, .hoist_data=null})
						catch unreachable;
				}
			}
			else{
				new.append(Token{.tag=.IDENTIFIER, .text=id, .hoist_data=null})
					catch unreachable;
			}
			continue :outer;
		}
		var arg_index: u64 = 0;
		while (arg_index < stack.items.len) : (arg_index += 1){
			const arg = stack.items[arg_index];
			if (!token_equal(token, &arg.arg.name)){
				continue;
			}
			if (arg.arg.pattern == Pattern.alternate){
				if (index < current_bind.text.items.len){
					if (current_bind.text.items[index+1].tag == .OPEN_BRACK){
						for (arg.nodes.items) |alt_arg| {
							stack.append(alt_arg)
								catch unreachable;
						}
						defer for (arg.nodes.items) |_| {
							_ = stack.pop();
						};
						index += 2;
						for (0..arg.alternate) |_| {
							var depth: u64 = 0;
							while (index < current_bind.text.items.len) : (index += 1){
								if (current_bind.text.items[index].tag == .ALTERNATE){
									if (depth == 0){
										index += 1;
										break;
									}
									continue;
								}
								if (current_bind.text.items[index].tag == .OPEN_BRACK){
									depth += 1;
									continue;
								}
								if (current_bind.text.items[index].tag == .CLOSE_BRACK){
									if (depth == 0){
										std.debug.print("Not enough alternate expansions for alternate applied in bind argument\n", .{});
										return ParseError.AlternateUnmatchable;
									}
									depth -= 1;
								}
							}
						}
						index = try rewrite(mem, outer_binds, current, new, index, false, true, stack);
						var depth: u64 = 0;
						while (index < current_bind.text.items.len) : (index += 1){
							if (current_bind.text.items[index].tag == .OPEN_BRACK){
								depth += 1;
								continue;
							}
							if (current_bind.text.items[index].tag == .CLOSE_BRACK){
								if (depth == 0){
									break;
								}
								depth -= 1;
							}
						}
						continue :outer;
					}
				}
				std.debug.assert(arg.expansion != null);
				for (arg.expansion.?) |*tok| {
					var tmp_tok = tok.*;
					if (first){
						first = false;
						if (current_bind.hoist_token) |_| {
							if (tmp_tok.hoist_data) |_|{
								tmp_tok.hoist_data.?.append(current)
									catch unreachable;
							}
							else{
								var hd = Buffer(AppliedBind).init(mem.*);
								hd.append(current)
									catch unreachable;
								tmp_tok.hoist_data = hd;
							}
						}
					}
					new.append(tmp_tok)
						catch unreachable;
				}
				continue :outer;
			}
			if (arg.arg.pattern == Pattern.variadic){
				if (index < current_bind.text.items.len){
					if (current_bind.text.items[index+1].tag == .OPEN_BRACE){
						const save_index = index+1;
						for (arg.nodes.items) |iter| {
							for (iter.nodes.items) |iter_arg| {
								stack.append(iter_arg)
									catch unreachable;
							}
							index = try rewrite(mem, outer_binds, current, new, save_index+1, true, false, stack);
							std.debug.assert(current_bind.text.items.len-1 == index);
							for (iter.nodes.items) |_| {
								_ = stack.pop();
							}
						}
						std.debug.assert(current_bind.text.items.len-1 == index);
						continue :outer;
					}
				}
				std.debug.assert(arg.expansion != null);
				for (arg.expansion.?) |*tok| {
					var tmp_tok = tok.*;
					if (first){
						first = false;
						if (current_bind.hoist_token) |_|{
							if (tmp_tok.hoist_data) |_|{
								tmp_tok.hoist_data.?.append(current)
									catch unreachable;
							}
							else{
								var hd = Buffer(AppliedBind).init(mem.*);
								hd.append(current)
									catch unreachable;
								tmp_tok.hoist_data = hd;
							}
						}
					}
					new.append(tmp_tok)
						catch unreachable;
				}
				continue :outer;
			}
			if (arg.arg.tag == .unique){
				continue :outer;
			}
			std.debug.assert(arg.expansion != null);
			for (arg.expansion.?) |*tok| {
				var tmp_tok = tok.*;
				if (first){
					first = false;
					if (current_bind.hoist_token)|_|{
						if (tmp_tok.hoist_data) |_|{
							tmp_tok.hoist_data.?.append(current)
								catch unreachable;
						}
						else{
							var hd = Buffer(AppliedBind).init(mem.*);
							hd.append(current)
								catch unreachable;
							tmp_tok.hoist_data = hd;
						}
					}
				}
				new.append(tmp_tok)
					catch unreachable;
			}
			continue :outer;
		}
		var tmp_tok = token.*;
		if (first){
			first = false;
			if (current_bind.hoist_token)|_|{
				if (tmp_tok.hoist_data) |_|{
					tmp_tok.hoist_data.?.append(current)
						catch unreachable;
				}
				else{
					var hd = Buffer(AppliedBind).init(mem.*);
					hd.append(current)
						catch unreachable;
					tmp_tok.hoist_data = hd;
				}
			}
		}
		new.append(tmp_tok)
			catch unreachable;
	}
	return index;
}

pub fn concat_pass(mem: *const std.mem.Allocator, aux: *Buffer(Token), program: *const Buffer(Token)) ParseError!bool {
	var new = aux;
	new.clearRetainingCapacity();
	var concatenated = false;
	var index: u64 = 0;
	while (index < program.items.len-2) {
		const concat = program.items[index+1];
		if (concat.tag != .CONCAT){
			new.append(program.items[index])
				catch unreachable;
			index += 1;
			continue;
		}
		concatenated = true;
		const left = program.items[index];
		const right = program.items[index+2];
		const together = mem.alloc(u8, left.text.len+right.text.len)
			catch unreachable;
		var i:u64 = 0;
		while (i<left.text.len){
			together[i] = left.text[i];
			i += 1;
		}
		while ((i-left.text.len)<right.text.len) {
			together[i] = right.text[i-left.text.len];
			i += 1;
		}
		new.append(Token{.tag=.IDENTIFIER,.text=together, .hoist_data=null})
			catch unreachable;
		index += 3;
	}
	while (index < program.items.len) : (index += 1){
		new.append(program.items[index])
			catch unreachable;
	}
	return concatenated;
}

pub fn move_data(run: *Buffer(Token), comp: *const Buffer(Token), mem: *const std.mem.Allocator) ParseError!void {
	var token_index: u64 = 0;
	while (token_index < comp.items.len){
		skip_whitespace(comp.items, &token_index) catch {
			return;
		};
		if (token_index > comp.items.len){
			std.debug.print("Expected instruction data, found end of file\n", .{});
			return ParseError.UnexpectedEOF;
		}
		var token = comp.items[token_index];
		token_index += 1;
		if (token.tag == .COMP_MOVE){
			const loc = try parse_location(mem, comp, &token_index);
			token = comp.items[token_index];
			token_index += 1;
			if (token.tag != .COMP_MOVE){
				std.debug.print("Expected end of comp time move location, found {s}\n", .{token.text});
				return ParseError.UnexpectedToken;
			}
			token = mk_token_from_u64(mem, val64(loc) catch |err| {
				std.debug.print("Encountered error in comptime move value {}\n", .{err});
				return ParseError.UnexpectedToken;
			});
		}
		run.append(token)
			catch unreachable;
	}
}

pub fn mk_token_from_u64(mem: *const std.mem.Allocator, val: u64) Token {
	const buf = mem.alloc(u8, 20) catch unreachable;
	const slice = std.fmt.bufPrint(buf, "{}", .{val}) catch unreachable;
	return Token{.tag=.IDENTIFIER, .text=slice, .hoist_data=null};
}

pub fn rewrite_hoist(mem: *const std.mem.Allocator, outer_binds: *Buffer(Bind), current: AppliedBind, new: *Buffer(Token), input_index: u64, varnest: bool, altnest: bool, stack: *Buffer(*ArgTree)) ParseError!u64 {
	for (current.expansions.items) |applied| {
		stack.append(applied)
			catch unreachable;
	}
	defer for (current.expansions.items) |_| {
		_ = stack.pop();
	};
	var index: u64 = input_index;
	var nest_depth: u64 = 0;
	var current_bind = outer_binds.items[current.bind];
	outer: while (index < current_bind.hoist.items.len) : (index += 1){
		const token = &current_bind.hoist.items[index];
		if (altnest){
			if (token.tag == .ALTERNATE or token.tag == .CLOSE_BRACK){
				if (nest_depth == 0){
					break :outer;
				}
				if (token.tag == .CLOSE_BRACK){
					nest_depth -= 1;
				}
			}
			else if (token.tag == .OPEN_BRACK){
				nest_depth += 1;
			}
		}
		else if (varnest){
			if (token.tag == .CLOSE_BRACE){
				if (nest_depth == 0){
					break :outer;
				}
				nest_depth -= 1;
			}
			if (token.tag == .OPEN_BRACE){
				nest_depth += 1;
			}
		}
		if (current.uniques.get(token.text)) |id| {
			new.append(Token{.tag=.IDENTIFIER, .text=id, .hoist_data=null})
				catch unreachable;
			continue :outer;
		}
		var arg_index: u64 = 0;
		while (arg_index < stack.items.len) : (arg_index += 1){
			const arg = stack.items[arg_index];
			if (!token_equal(token, &arg.arg.name)){
				continue;
			}
			if (arg.arg.pattern == Pattern.alternate){
				if (index < current_bind.hoist.items.len){
					if (current_bind.hoist.items[index+1].tag == .OPEN_BRACK){
						for (arg.nodes.items) |alt_arg| {
							stack.append(alt_arg)
								catch unreachable;
						}
						defer for (arg.nodes.items) |_| {
							_ = stack.pop();
						};
						index += 2;
						for (0..arg.alternate) |_| {
							var depth: u64 = 0;
							while (index < current_bind.hoist.items.len) : (index += 1){
								if (current_bind.hoist.items[index].tag == .ALTERNATE){
									if (depth == 0){
										index += 1;
										break;
									}
									continue;
								}
								if (current_bind.hoist.items[index].tag == .OPEN_BRACK){
									depth += 1;
									continue;
								}
								if (current_bind.hoist.items[index].tag == .CLOSE_BRACK){
									if (depth == 0){
										std.debug.print("Not enough alternate expansions for alternate applied in bind argument\n", .{});
										return ParseError.AlternateUnmatchable;
									}
									depth -= 1;
								}
							}
						}
						index = try rewrite(mem, outer_binds, current, new, index, false, true, stack);
						var depth: u64 = 0;
						while (index < current_bind.hoist.items.len) : (index += 1){
							if (current_bind.hoist.items[index].tag == .OPEN_BRACK){
								depth += 1;
								continue;
							}
							if (current_bind.hoist.items[index].tag == .CLOSE_BRACK){
								if (depth == 0){
									break;
								}
								depth -= 1;
							}
						}
						continue :outer;
					}
				}
				std.debug.assert(arg.expansion != null);
				for (arg.expansion.?) |*tok| {
					const tmp_tok = tok.*;
					new.append(tmp_tok)
						catch unreachable;
				}
				continue :outer;
			}
			if (arg.arg.pattern == Pattern.variadic){
				if (index < current_bind.hoist.items.len){
					if (current_bind.hoist.items[index+1].tag == .OPEN_BRACE){
						const save_index = index+1;
						for (arg.nodes.items) |iter| {
							for (iter.nodes.items) |iter_arg| {
								stack.append(iter_arg)
									catch unreachable;
							}
							index = try rewrite(mem, outer_binds, current, new, save_index+1, true, false, stack);
							std.debug.assert(current_bind.hoist.items.len-1 == index);
							for (iter.nodes.items) |_| {
								_ = stack.pop();
							}
						}
						std.debug.assert(current_bind.hoist.items.len-1 == index);
						continue :outer;
					}
				}
				std.debug.assert(arg.expansion != null);
				for (arg.expansion.?) |*tok| {
					const tmp_tok = tok.*;
					new.append(tmp_tok)
						catch unreachable;
				}
				continue :outer;
			}
			if (arg.arg.tag == .unique){
				continue :outer;
			}
			std.debug.assert(arg.expansion != null);
			for (arg.expansion.?) |*tok| {
				const tmp_tok = tok.*;
				new.append(tmp_tok)
					catch unreachable;
			}
			continue :outer;
		}
		const tmp_tok = token.*;
		new.append(tmp_tok)
			catch unreachable;
	}
	return index;
}

pub fn new_uid(mem: *const std.mem.Allocator) []u8 {
	var new = mem.alloc(u8, uid.len) catch unreachable;
	var i:u64 = 0;
	var inc:bool = false;
	while (i < new.len) {
		if (uid[i] < 'Z'){
			new[i] = uid[i]+1;
			break;
		}
		new[i] = 'A';
		inc = true;
		i += 1;
	}
	if (inc){
		new[i] = uid[i]+1;
	}
	while (i < new.len){
		new[i] = uid[i];
		i += 1;
	}
	return new;
}

pub fn apply_whitespace(input_index: u64, tokens: []Token) u64 {
	var token_index = input_index;
	while (token_index < tokens.len){
		if (tokens[token_index].tag == .SPACE){
			token_index += 1;
			continue;
		}
		if (tokens[token_index].tag == .TAB){
			token_index += 1;
			continue;
		}
		if (tokens[token_index].tag == .NEW_LINE){
			token_index += 1;
			continue;
		}
		break;
	}
	return token_index;
}

const Location = union(enum) {
	immediate: u64,
	literal: u64,
	register: TOKEN,
	dereference: *Location
};

const Instruction = union(enum) {
	move: struct {
		dest: Location,
		src: Location
	},
	compare: struct {
		left: Location,
		right: Location
	},
	alu: struct {
		tag: TOKEN,
		dest: Location,
		left: Location,
		right: Location
	},
	jump: struct {
		tag: TOKEN,
		dest: Location
	},
	interrupt,
};

pub fn parse_bytecode(mem: *const std.mem.Allocator, tokens: *const Buffer(Token), token_index: *u64, comp: bool) ParseError!Buffer(Instruction) {
	try retokenize(mem, tokens);
	var ops = Buffer(Instruction).init(mem.*);
	var labels = std.StringHashMap(u64).init(mem.*);
	const index_save = token_index.*;
	for (0..2) |_| {
		token_index.* = index_save;
		ops.clearRetainingCapacity();
		while (token_index.* < tokens.items.len){
			skip_whitespace(tokens.items, token_index) catch {
				return ops;
			};
			if (token_index.* > tokens.items.len){
				std.debug.print("Expected opcode, found end of file\n", .{});
				return ParseError.UnexpectedEOF;
			}
			const token = tokens.items[token_index.*];
			token_index.* += 1;
			switch (token.tag){
				.COMP_START => {
					comp_section = true;
					if (debug) {
						std.debug.print("Entering comp segment\n", .{});
					}
					const comp_program = try parse_bytecode(mem, tokens, token_index, true);
					if (debug) {
						std.debug.print("Parsed comp segment\n", .{});
					}
					interpret(comp_program) catch |err| {
						std.debug.print("Runtime Error {}\n", .{err});
						return ParseError.BrokenComptime;
					};
					if (debug) {
						std.debug.print("Exiting comp segment\n", .{});
					}
					comp_section = false;
				},
				.COMP_END => {
					if (comp == false){
						continue;
					}
					return ops;
				},
				.BIND => {
					skip_whitespace(tokens.items, token_index) catch {
						return ops;
					};
					token_index.* += 1;
					skip_whitespace(tokens.items, token_index) catch {
						return ops;
					};
					const name = tokens.items[token_index.*];
					token_index.* += 1;
					if (name.tag != .IDENTIFIER){
						std.debug.print("Expected name for transfer bind, found {s}\n", .{name.text});
						return ParseError.UnexpectedToken;
					}
					skip_whitespace(tokens.items, token_index) catch {
						return ops;
					};
					if (tokens.items[token_index.*].tag != .EQUAL){
						std.debug.print("Expected = for transfer bind, found {s}\n", .{tokens.items[token_index.*].text});
						return ParseError.UnexpectedToken;
					}
					token_index.* += 1;
					skip_whitespace(tokens.items, token_index) catch {
						return ops;
					};
					const is_ip = tokens.items[token_index.*];
					if (is_ip.tag == .IP){
						token_index.* += 1;
						labels.put(name.text, ops.items.len)
							catch unreachable;
						continue;
					}
					const loc = try parse_location(mem, tokens, token_index);
					const val = val64(loc) catch |err| {
						std.debug.print("Encountered error in Persistence binding: {}\n", .{err});
						return ParseError.UnexpectedToken;
					};
					if (comp){
						if (debug){
							std.debug.print("comp persistent put {s} : {}\n", .{name.text, val});
						}
						comp_persistent.put(name.text, val)
							catch unreachable;
					}
					else{
						std.debug.print("persistent put {s} : {}\n", .{name.text, val});
						persistent.put(name.text, val)
							catch unreachable;
					}
				},
				.MOV => {
					ops.append(
						Instruction{
							.move=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels),
								.src=try parse_location_or_label(mem, tokens, token_index, labels)
							}
						}
					) catch unreachable;
				},
				.ADD, .SUB, .MUL, .DIV => {
					ops.append(
						Instruction{
							.alu=.{
								.tag = token.tag,
								.dest=try parse_location_or_label(mem, tokens, token_index, labels),
								.left=try parse_location_or_label(mem, tokens, token_index, labels),
								.right=try parse_location_or_label(mem, tokens, token_index, labels)
							}
						}
					) catch unreachable;
				},
				.CMP => {
					ops.append(
						Instruction{
							.compare=.{
								.left=try parse_location_or_label(mem, tokens, token_index, labels),
								.right=try parse_location_or_label(mem, tokens, token_index, labels)
							}
						}
					) catch unreachable;
				},
				.JMP, .JLT, .JGT, .JLE, .JGE, .JZ, .JNZ, .JEQ, .JNE => {
					ops.append(
						Instruction{
							.jump=.{
								.tag=token.tag,
								.dest=try parse_location_or_label(mem, tokens, token_index, labels)
							}
						}
					) catch unreachable;
				},
				.INT => {
					ops.append(
						Instruction{
							.interrupt={}
						}
					) catch unreachable;
				},
				else => {
					std.debug.print("Expected opcode, found {s}\n", .{token.text});
					return ParseError.UnexpectedToken;
				}
			}
		}
	}
	return ops;
}

pub fn parse_location_or_label(mem: *const std.mem.Allocator, tokens: *const Buffer(Token), token_index: *u64, labels: std.StringHashMap(u64)) ParseError!Location {
	try skip_whitespace(tokens.items, token_index);
	if (token_index.* > tokens.items.len){
		std.debug.print("Expected operand for instruction, found end of file\n", .{});
		return ParseError.UnexpectedEOF;
	}
	var token = tokens.items[token_index.*];
	if (labels.get(token.text)) |label_val| {
		token_index.* += 1;
		return Location {.literal=label_val};
	}
	if (token.tag == .OPEN_BRACK){
		token_index.* += 1;
		const reference = try parse_location(mem, tokens, token_index);
		const location = mem.create(Location) catch
			unreachable;
		location.* = reference;
		if (tokens.items[token_index.*].tag != .CLOSE_BRACK){
			std.debug.print("Expected close bracket for dereferenced location\n", .{});
			return ParseError.UnexpectedToken;
		}
		token_index.* += 1;
		return Location{
			.dereference=location
		};
	}
	switch (token.tag){
		.R0, .R1, .R2, .R3 => {
			token_index.* += 1;
			return Location{
				.register=token.tag
			};
		},
		.IP => {
			token_index.* += 1;
			return Location {
				.literal=0
			};
		},
		.IDENTIFIER => {
			token_index.* += 1;
			return Location{
				.immediate = hash_global_enum(token)
			};
		},
		.LIT => {
			token_index.* += 1;
			token = tokens.items[token_index.*];
			token_index.* += 1;
			if (token.tag != .IDENTIFIER) {
				std.debug.print("Expected indentifier to serve as immediate value, found {s}\n", .{token.text});
				return ParseError.UnexpectedToken;
			}
			return Location{
				.literal = hash_global_enum(token)
			};
		},
		else => {
			std.debug.print("Expected operand, found {s}\n", .{token.text});
			return ParseError.UnexpectedToken;
		}
	}
}

pub fn parse_location(mem: *const std.mem.Allocator, tokens: *const Buffer(Token), token_index: *u64) ParseError!Location {
	try skip_whitespace(tokens.items, token_index);
	if (token_index.* > tokens.items.len){
		std.debug.print("Expected operand for instruction, found end of file\n", .{});
		return ParseError.UnexpectedEOF;
	}
	var token = tokens.items[token_index.*];
	if (token.tag == .OPEN_BRACK){
		token_index.* += 1;
		const reference = try parse_location(mem, tokens, token_index);
		const location = mem.create(Location) catch
			unreachable;
		location.* = reference;
		if (tokens.items[token_index.*].tag != .CLOSE_BRACK){
			std.debug.print("Expected close bracket for dereferenced location\n", .{});
			return ParseError.UnexpectedToken;
		}
		token_index.* += 1;
		return Location{
			.dereference=location
		};
	}
	switch (token.tag){
		.R0, .R1, .R2, .R3 => {
			token_index.* += 1;
			return Location{
				.register=token.tag
			};
		},
		.IP => {
			token_index.* += 1;
			return Location {
				.literal=0
			};
		},
		.IDENTIFIER => {
			token_index.* += 1;
			return Location{
				.immediate = hash_global_enum(token)
			};
		},
		.LIT => {
			token_index.* += 1;
			token = tokens.items[token_index.*];
			token_index.* += 1;
			if (token.tag != .IDENTIFIER) {
				std.debug.print("Expected indentifier to serve as immediate value, found {s}\n", .{token.text});
				return ParseError.UnexpectedToken;
			}
			return Location{
				.literal = hash_global_enum(token)
			};
		},
		else => {
			std.debug.print("Expected operand, found {s}\n", .{token.text});
			return ParseError.UnexpectedToken;
		}
	}
}

pub fn hash_global_enum(token: Token) u64 {
	const value = std.fmt.parseInt(u64, token.text, 10) catch {
		if (comp_section){
			if (comp_persistent.get(token.text)) |val| {
				return val;
			}
		}
		else{
			if (persistent.get(token.text)) |val| {
				return val;
			}
		}
		if (iden_hashes.get(token.text)) |id| {
			return id;
		}
		iden_hashes.put(token.text, current_iden)
			catch unreachable;
		current_iden += 1;
		return current_iden-1;
	};
	return value;
}

pub fn show_instruction(inst: *const Instruction) void {
	if (!debug){
		return;
	}
	switch (inst.*){
		.move => {
			std.debug.print("mov ", .{});
			show_location(&inst.move.dest);
			show_location(&inst.move.src);
			std.debug.print("\n", .{});
		},
		.compare => {
			std.debug.print("cmp ", .{});
			show_location(&inst.compare.left);
			show_location(&inst.compare.right);
			std.debug.print("\n", .{});
		},
		.alu => {
			std.debug.print("{} ", .{inst.alu.tag});
			show_location(&inst.alu.dest);
			show_location(&inst.alu.left);
			show_location(&inst.alu.right);
			std.debug.print("\n", .{});
		},
		.jump => {
			std.debug.print("{} ", .{inst.jump.tag});
			show_location(&inst.jump.dest);
			std.debug.print("\n", .{});
		},
		.interrupt => {
			std.debug.print("int\n", .{});
		}
	}
}

pub fn show_instructions(instructions: Buffer(Instruction)) void {
	if (!debug){
		return;
	}
	for (instructions.items) |*inst| {
		show_instruction(inst);
	}
}

pub fn show_location(loc: *const Location) void {
	if (!debug){
		return;
	}
	switch (loc.*){
		.immediate => {
			std.debug.print("{} ", .{loc.immediate});
		},
		.literal => {
			std.debug.print("!{} ", .{loc.literal});
		},
		.register => {
			std.debug.print("{} ", .{loc.register});
		},
		.dereference => {
			std.debug.print("[", .{});
			show_location(loc.dereference);
			std.debug.print("] ", .{});
		}
	}
}

pub fn fill_hoist(mem: *const std.mem.Allocator, aux: *Buffer(Token), program: *const Buffer(Token), binds: *Buffer(Bind)) ParseError!bool {
	var new = aux;
	new.clearRetainingCapacity();
	var hoisted = false;
	for (program.items) |*token| {
		if (token.hoist_data) |*hoist_data| {
			var hoist_index = hoist_data.items.len;
			while (hoist_index > 0){
				hoist_index -= 1;
				const hoist = hoist_data.items[hoist_index];
				hoisted = true;
				var index = new.items.len;
				var uniques = std.StringHashMap([]u8).init(mem.*);
				var found = false;
				defer uniques.deinit();
				while (index > 0){
					const tree = apply_rule(mem, &uniques, &binds.items[hoist.bind].hoist_token.?, new.items, index-1, 0) catch {
						index -= 1;
						continue;
					};
					if (tree) |seq| {
						std.debug.assert(seq.expansion != null);
						var pos = index-1;
						var temp = Buffer(Token).init(mem.*);
						defer temp.deinit();
						while (pos < new.items.len){
							temp.append(new.items[pos])
								catch unreachable;
							pos += 1;
						}
						new.items.len = index-1;
						var stack = Buffer(*ArgTree).init(mem.*);
						_ = try rewrite_hoist(mem, binds, hoist, new, 0, false, false, &stack);
						for (temp.items) |relay| {
							new.append(relay)
								catch unreachable;
						}
						found = true;
						break;
					}
					unreachable;
				}
				if (found){
					_ = hoist_data.orderedRemove(hoist_index);
				}
			}
			if (hoist_data.items.len == 0){
				token.hoist_data = null;
			}
		}
		new.append(token.*)
			catch unreachable;
	}
	return hoisted;
}

const RuntimeError = error {
	UnknownRegister,
	UnknownALU,
	UnknownJump,
	LiteralAssignment
};

pub fn load_u64(addr: u64) u64 {
	var tmp: [8]u8 = undefined;
    @memcpy(&tmp, vm.mem[addr .. addr + 8]);
    return @bitCast(tmp);	
}

pub fn store_u64(addr: u64, val: u64) void {
	const bytes: [8]u8 = @bitCast(val);
    @memcpy(vm.mem[addr .. addr + 8], &bytes);	
}

pub fn loc64(l: Location, val: u64) RuntimeError!void {
	switch (l){
		.immediate => {
			store_u64(l.immediate, val);
		},
		.literal => {
			return RuntimeError.LiteralAssignment;
		}, 
		.register => {
			switch (l.register){
				.R0 => {store_u64(vm.r0, val);},
				.R1 => {store_u64(vm.r1, val);},
				.R2 => {store_u64(vm.r2, val);},
				.R3 => {store_u64(vm.r3, val);},
				else => {
					return RuntimeError.UnknownRegister;
				}
			}
		},
		.dereference => {
			const inner = try val64(l.dereference.*);
			store_u64(inner, val);
		}
	}
}

pub fn val64(l: Location) RuntimeError!u64 {
	switch (l){
		.immediate => {
			return load_u64(l.immediate);
		},
		.literal => {
			return l.literal;
		},
		.register => {
			switch (l.register){
				.R0 => {return load_u64(vm.r0);},
				.R1 => {return load_u64(vm.r1);},
				.R2 => {return load_u64(vm.r2);},
				.R3 => {return load_u64(vm.r3);},
				else => {
					return RuntimeError.UnknownRegister;
				}
			}
		},
		.dereference => {
			const inner = try val64(l.dereference.*);
			return load_u64(inner);
		}
	}
	unreachable;
}

pub fn interpret(instructions: Buffer(Instruction)) RuntimeError!void {
	var ip: u64 = 0;
	while (ip < instructions.items.len){
		const inst = instructions.items[ip];
		show_instruction(&inst);
		switch (inst){
			.move => {
				const val = try val64(inst.move.src);
				if (debug){
					std.debug.print("src: {}\n", .{val});
				}
				try loc64(inst.move.dest, val);
				ip += 1;
			},
			.compare => {
				const left = try val64(inst.compare.left);
				const right = try val64(inst.compare.right);
				if (debug){
					std.debug.print("left: {}, right: {}\n", .{left, right});
				}
				if (left > right) {
					vm.mem[vm.sr] = 1;
				}
				else if (left < right) {
					vm.mem[vm.sr] = 2;
				}
				vm.mem[vm.sr] = 0;
				ip += 1;
			},
			.alu => {
				switch (inst.alu.tag){
					.ADD => {
						const left = try val64(inst.alu.left);
						const right = try val64(inst.alu.right);
						if (debug){
							std.debug.print("left: {}, right: {}\n", .{left, right});
						}
						try loc64(inst.alu.dest, left+right);
					},
					.SUB => { 
						const left = try val64(inst.alu.left);
						const right = try val64(inst.alu.right);
						if (debug){
							std.debug.print("left: {}, right: {}\n", .{left, right});
						}
						try loc64(inst.alu.dest, left-right);
					},
					.MUL => { 
						const left = try val64(inst.alu.left);
						const right = try val64(inst.alu.right);
						if (debug){
							std.debug.print("left: {}, right: {}\n", .{left, right});
						}
						try loc64(inst.alu.dest, left*right);
					},
					.DIV => { 
						const left = try val64(inst.alu.left);
						const right = try val64(inst.alu.right);
						if (debug){
							std.debug.print("left: {}, right: {}\n", .{left, right});
						}
						try loc64(inst.alu.dest, left/right);
					},
					else => {
						return RuntimeError.UnknownALU;
					}
				}
				ip += 1;
			},
			.jump => {
				switch(inst.jump.tag){
					.JMP => {
						ip = try val64(inst.jump.dest);
						continue;
					},
					.JEQ => {
						if (load_u64(vm.sr) == 0){
							ip = try val64(inst.jump.dest);
							continue;
						}
					},
					.JNE => {
						if (load_u64(vm.sr) != 0){
							ip = try val64(inst.jump.dest);
							continue;
						}
					},
					.JLT => {
						if (load_u64(vm.sr) == 2){
							ip = try val64(inst.jump.dest);
							continue;
						}
					},
					.JGT => {
						if (load_u64(vm.sr) == 1){
							ip = try val64(inst.jump.dest);
							continue;
						}
					},
					.JLE => {
						if (load_u64(vm.sr) != 1){
							ip = try val64(inst.jump.dest);
							continue;
						}
					},
					.JGE => {
						if (load_u64(vm.sr) != 2){
							ip = try val64(inst.jump.dest);
							continue;
						}
					},
					.JZ => {
						if (load_u64(vm.sr) == 0){
							ip = try val64(inst.jump.dest);
							continue;
						}
					},
					.JNZ => {
						if (load_u64(vm.sr) != 0){
							ip = try val64(inst.jump.dest);
							continue;
						}
					},
					else => {
						return RuntimeError.UnknownJump;
					}
				}
				ip += 1;
			},
			.interrupt => {
				//TODO propper interrupts
				ip += 1;
				if (vm.mem[vm.r0] == 0){
					const pos = vm.mem[vm.r1];
					const len = vm.mem[vm.r2];
					for (0..len) |i| {
						std.debug.print("{}", .{vm.mem[pos+i]});
					}
				}
			}
		}
	}
}

//pub fn serialize(mem: *const std.mem.Allocator, instructions: Buffer(Instruction)) !void {
	//var file = try std.fs.cwd().createFile(
		//"out.bin",
		//.{.truncate=true}
	//);
	//defer file.close();
	//var data = Buffer(u8).init(mem.*);
	//for (instructions.items) |inst| {
		//switch (inst){
			//.move => {
				//data.append(0x01)
					//catch unreachable;
				//write_location(&data, inst.move.dest);
				//write_location(&data, inst.move.src);
			//},
			//.alu => {
				//data.append(@intFromEnum(inst.alu.tag))
					//catch unreachable;
				//write_location(&data, inst.move.dest);
				//write_location(&data, inst.move.left);
				//write_location(&data, inst.move.right);
			//},
			//.compare => {
				//data.append(0x02)
					//catch unreachable;
				//write_location(&data, inst.move.left);
				//write_location(&data, inst.move.right);
			//},
			//.jump => {
				//data.append(@intFromEnum(inst.jump.tag))
					//catch unreachable;
				//write_location(&data, inst.move.dest);
			//},
			//.interrupt => {
				//data.append(0x03)
					//catch unreachable;
			//}
		//}
	//}
	//try file.writeAll(data.items);
//}
//
//pub fn write_location(data: *Buffer(u8), loc: Location) void {
	//switch(loc){
		//.immediate => {
			//data.append(loc.immediate)
				//catch unreachable;
		//},
		//.literal => {
			//data.append(0x04)
				//catch unreachable;
			//data.append(loc.literal)
				//catch unreachable;
		//},
		////TODO uh oh this is too simple and doesnt work lol
	//}
//}
//

//TODO serialization properly
//TODO loading
//TODO more instructions
	//alu shifts
	//logical operators
	//mov instructions
//TODO emulated hardware components of the virtual computer
//TODO metaprogram parse operation as an interrupt
	// interrupts: write n to file, read n from file, get input from keyboard/mouse, send info to screen
//TODO think about debugging infrastructure
//TODO introduce propper debugger state

