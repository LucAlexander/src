const std = @import("std");
const Buffer = std.ArrayList;

const uid: []const u8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

var iden_hashes = std.StringHashMap(u64).init(std.heap.page_allocator);
var current_iden: u64 = 0;

const VM = struct {
	mem: [10000]u8,
	r0: u64,
	r1: u64,
	r2: u64,
	r3: u64,
	sr: u64,
	
	pub fn init() VM {
		return VM{
			.mem=undefined,
			.r0=0,
			.r1=0,
			.r2=0,
			.r3=0,
			.sr=0
		};
	}
};

var vm: VM = VM.init();

pub fn main() !void {
	const allocator = std.heap.page_allocator;
	var infile = try std.fs.cwd().openFile("bytecode.src", .{});
	defer infile.close();
	const stat = try infile.stat();
	const contents = try infile.readToEndAlloc(allocator, stat.size+1);
	defer allocator.free(contents);
	var main_mem = std.heap.ArenaAllocator.init(allocator);
	defer main_mem.deinit();
	const mem = main_mem.allocator();
	const tokens = tokenize(&mem, contents);
	show_tokens(tokens);
	std.debug.print("initial------------------------------\n", .{});
	metaprogram(&tokens, Buffer(Bind).init(mem), &mem);
}

pub fn metaprogram(tokens: *const Buffer(Token), binds: Buffer(Bind), mem: *const std.mem.Allocator) void {
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
	var done = false;
	var token_index: u64 = 0;
	program.text=&text;
	while (!done){
		program.text.clearRetainingCapacity();
		token_index = 0;
		done = parse(mem, token_stream, &program, &token_index) catch |err| {
			std.debug.print("Parse Error {}\n", .{err});
			report_error(token_stream, token_index);
			return;
		};
		show_program(program);
		std.debug.print("parsed--------------------------\n", .{});
		if (done){
			break;
		}
		if (program.text == &text){
			token_stream = apply_binds(mem, &text, &auxil, &program) catch |err| {
				std.debug.print("Parse Error {}\n", .{err});
				return;
			};
		}
		else {
			token_stream = apply_binds(mem, &auxil, &text, &program) catch |err| {
				std.debug.print("Parse Error {}\n", .{err});
				return;
			};
		}
		show_tokens(token_stream.*);
		std.debug.print("applied binds-------------------\n", .{});
	}
	const instructions = parse_bytecode(mem, token_stream) catch |err| {
		std.debug.print("Bytecode Parse Error {}\n", .{err});
		return;
	};
	show_instructions(instructions);
	//TODO run
}

const ParseError = error {
	PrematureEnd,
	UnexpectedToken,
	UnexpectedEOF,
	AlternateUnmatchable
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
	LIT,
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
	tag: TOKEN
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
	tag: enum {
		rewrite,
		compile,
		pattern
	},
	precedence: u8,
	args: Buffer(Arg),
	hoist: Buffer(Token),
	hoist_token: ?Token,
	text: Buffer(Token)
};

//TODO memory optimization
const ArgTree = struct {
	nodes: Buffer(*ArgTree),
	arg: Arg,
	alternate: u64,
	expansion: ?[]Token,
	
	pub fn init(mem: *const std.mem.Allocator, arg: Arg, exp: ?[]Token) *ArgTree {
		const tree = ArgTree {
			.arg=arg,
			.expansion=exp,
			.alternate=0,
			.nodes=Buffer(*ArgTree).init(mem.*)
		};
		const loc = mem.create(ArgTree) catch unreachable;
		loc.* = tree;
		return loc;
	}
};

const AppliedBind = struct {
	bind: *Bind,
	expansions: Buffer(*ArgTree),
	uniques: std.StringHashMap([]u8),
	start_index: u64,
	end_index: u64
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
		tokens.append(Token{.tag=tag, .text=keyword})
			catch unreachable;
		i += size;
	}
	return tokens;
}

pub fn show_tokens(tokens: Buffer(Token)) void {
	for (tokens.items) |*token| {
		std.debug.print("{} {s}\n", .{token.tag, token.text});
	}
	std.debug.print("\n", .{});
}

pub fn parse(mem: *const std.mem.Allocator, tokens: *const Buffer(Token), program: *ProgramText, token_index: *u64) !bool {
	var done = true;
	while (token_index.* < tokens.items.len){
		const token = &tokens.items[token_index.*];
		if (token.tag != .BIND and
			token.tag != .BIND_COMP and
			token.tag != .BIND_PATTERN){
			program.text.append(token.*)
				catch unreachable;
			token_index.* += 1;
			continue;
		}
		done = false;
		program.binds.append(try parse_bind(mem, tokens.items, token_index))
			catch unreachable;
	}
	return done;
}

pub fn parse_bind(mem: *const std.mem.Allocator, tokens: []Token, token_index: *u64) !Bind {
	std.debug.assert(
		tokens[token_index.*].tag == .BIND or
		tokens[token_index.*].tag == .BIND_COMP or
		tokens[token_index.*].tag == .BIND_PATTERN
	);
	var bind = Bind{
		.tag = .rewrite,
		.precedence=0,
		.args=Buffer(Arg).init(mem.*),
		.hoist=Buffer(Token).init(mem.*),
		.hoist_token=null,
		.text=Buffer(Token).init(mem.*)
	};
	if (tokens[token_index.*].tag == .BIND_COMP){
		bind.tag = .compile;
	}
	else if (tokens[token_index.*].tag == .BIND_PATTERN){
		bind.tag = .pattern;
	}
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
		if (token.tag == .OPEN_BRACE){
			break;
		}
		bind.args.append(try parse_arg(mem, tokens, token_index))
			catch unreachable;
	}
	try skip_whitespace(tokens, token_index);
	std.debug.assert(tokens[token_index.*].tag == .OPEN_BRACE);
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
	try split_hoist(&bind);
	return bind;
}

pub fn split_hoist(bind: *Bind) ParseError!void {
	var last = bind.text.items[0];
	for (bind.text.items, 0..) |tok, i| {
		if (tok.tag == .HOIST){
			if (i == 0){
				std.debug.print("Required hoist token to hoist", .{});
				return ParseError.UnexpectedToken;
			}
			bind.hoist_token = last;
			var index: u64 = 0;
			while (index < i-1){
				bind.hoist.append(bind.text.items[index])
					catch unreachable;
				index += 1;
			}
			index += 2;
			var offset: u64 = 0;
			while (index < bind.text.items.len) {
				bind.text.items[offset] = bind.text.items[index];
				index += 1;
				offset += 1;
			}
			bind.text.items.len = offset;
			return;
		}
		last = tok;
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
	return ParseError.UnexpectedEOF;
}

pub fn parse_arg(mem: *const std.mem.Allocator, tokens: []Token, token_index: *u64) ParseError!Arg {
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
		std.debug.print("Expected either - ? or + to head non keyword argument, found {} {s}\n", .{tokens[token_index.*].tag, tokens[token_index.*].text});
		return ParseError.UnexpectedToken;
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
					try skip_whitespace(tokens, token_index);
					break;
				}
				if (tokens[token_index.*].tag == .CLOSE_BRACK){
					token_index.* += 1;
					try skip_whitespace(tokens, token_index);
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
	if (tokens[token_index.*].tag != .ELIPSES){
		std.debug.print("Expected elipses ... for grouping expression, found {s}\n", .{tokens[token_index.*].text});
		return ParseError.UnexpectedToken;
	}
	token_index.* += 1;
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
	show_tokens(program.text.*);
	std.debug.print("end text -----------\n", .{});
	for (program.binds.items) |bind| {
		std.debug.print("{}: precedence {}\nargs:\n", .{bind.tag, bind.precedence});
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
		.alternate => {
			var list = Buffer(*ArgTree).init(mem.*);
			blk: for (pattern.alternate.items, 0..) |*seqlist, alt| {
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
						temp_index += seq.expansion.?.len;
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
				temp_index += seq.expansion.?.len;
			}
			while (temp_index < tokens.len){
				const close_sequence = apply_rule(mem, uniques, pattern.group.close, tokens, temp_index, var_depth) catch {
					temp_index += 1;
					continue;
				};
				if (close_sequence) |close| {
					std.debug.assert(close.expansion != null);
					list.append(close)
						catch unreachable;
					temp_index += close.expansion.?.len;
				}
				break;
			}
			const tree = ArgTree.init(mem, name, tokens[token_index..temp_index]);
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
						temp_index += seq.expansion.?.len;
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
					temp_index += sep.expansion.?.len;
				}
				superlist.append(sublist)
					catch unreachable;
				times += 1;
			}
		}
	}
	unreachable;
}

pub fn apply_bind(mem: *const std.mem.Allocator, bind: *Bind, tokens: []Token, token_index: *u64) ?AppliedBind {
	const save_index = token_index.*;
	var list = Buffer(*ArgTree).init(mem.*);
	var uniques = std.StringHashMap([]u8).init(mem.*);
	for (bind.args.items) |*arg| {
		const sequence = apply_rule(mem, &uniques, arg, tokens, token_index.*, 0) catch {
			token_index.* = save_index;
			return null;
		};
		if (sequence) |seq| {
			std.debug.assert(seq.expansion != null);
			list.append(seq)
				catch unreachable;
			token_index.* += seq.expansion.?.len;
		}
	}
	return AppliedBind{
		.bind = bind,
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
		for (program.binds.items) |*bind| {
			if (bind.precedence != precedence){
				continue;
			}
			if (apply_bind(mem, bind, program.text.items, &i)) |applied| {
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

pub fn apply_binds(mem: *const std.mem.Allocator, txt: *Buffer(Token), aux: *Buffer(Token), program: *ProgramText) ParseError!*Buffer(Token) {
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
			token_index = current.end_index;
			var stack = Buffer(*ArgTree).init(mem.*);
			_ = try rewrite(mem, program.binds, current, new, 0, false, false, &stack);
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
				token_index = current.end_index;
				var adjust = false;
				if (current.end_index > next.start_index and current.end_index < next.end_index){
					adjust = true;
				}
				var stack = Buffer(*ArgTree).init(mem.*);
				_ = try rewrite(mem, program.binds, current, new, 0, false, false, &stack);
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
				token_index = current.end_index;
				var stack = Buffer(*ArgTree).init(mem.*);
				_ = try rewrite(mem, program.binds, current, new, 0, false, false, &stack);
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
			const stream = program.text;
			program.text = new;
			return stream;
		}
	}
	unreachable;
}

pub fn token_equal(a: *Token, b: *Token) bool {
	return std.mem.eql(u8, a.text, b.text);
}

pub fn rewrite(mem: *const std.mem.Allocator, outer_binds: Buffer(Bind), current: AppliedBind, new: *Buffer(Token), input_index: u64, varnest: bool, altnest: bool, stack: *Buffer(*ArgTree)) ParseError!u64 {
	for (current.expansions.items) |applied| {
		stack.append(applied)
			catch unreachable;
	}
	defer for (current.expansions.items) |_| {
		_ = stack.pop();
	};
	var index: u64 = input_index;
	var nest_depth: u64 = 0;
	outer: while (index < current.bind.text.items.len) : (index += 1){
		const token = &current.bind.text.items[index];
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
		if (token.tag == .CONCAT){
			const left = new.items[new.items.len-1].text;
			if (index+1 < current.bind.text.items.len){
				const right = current.bind.text.items[index+1].text;
				const concat = mem.alloc(u8, left.len+right.len)
					catch unreachable;
				var i:u64 = 0;
				while (i < left.len){
					concat[i] = left[i];
					i += 1;
				}
				while ((i-left.len) < right.len){
					concat[i] = right[i-left.len];
					i += 1;
				}
				new.items[new.items.len-1] = Token{.tag=.IDENTIFIER, .text=concat};
				index += 1;
				continue :outer;
			}
		}
		if (current.uniques.get(token.text)) |id| {
			new.append(Token{.tag=.IDENTIFIER, .text=id})
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
				if (index < current.bind.text.items.len){
					if (current.bind.text.items[index+1].tag == .OPEN_BRACK){
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
							while (index < current.bind.text.items.len) : (index += 1){
								if (current.bind.text.items[index].tag == .ALTERNATE){
									if (depth == 0){
										index += 1;
										break;
									}
									continue;
								}
								if (current.bind.text.items[index].tag == .OPEN_BRACK){
									depth += 1;
									continue;
								}
								if (current.bind.text.items[index].tag == .CLOSE_BRACK){
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
						while (index < current.bind.text.items.len) : (index += 1){
							if (current.bind.text.items[index].tag == .OPEN_BRACK){
								depth += 1;
								continue;
							}
							if (current.bind.text.items[index].tag == .CLOSE_BRACK){
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
					new.append(tok.*)
						catch unreachable;
				}
				continue :outer;
			}
			if (arg.arg.pattern == Pattern.variadic){
				if (index < current.bind.text.items.len){
					if (current.bind.text.items[index+1].tag == .OPEN_BRACE){
						const save_index = index+1;
						for (arg.nodes.items) |iter| {
							for (iter.nodes.items) |iter_arg| {
								stack.append(iter_arg)
									catch unreachable;
							}
							index = try rewrite(mem, outer_binds, current, new, save_index+1, true, false, stack);
							std.debug.assert(current.bind.text.items.len-1 == index);
							for (iter.nodes.items) |_| {
								_ = stack.pop();
							}
						}
						std.debug.assert(current.bind.text.items.len-1 == index);
						continue :outer;
					}
				}
				std.debug.assert(arg.expansion != null);
				for (arg.expansion.?) |*tok| {
					new.append(tok.*)
						catch unreachable;
				}
				continue :outer;
			}
			if (arg.arg.tag == .unique){
				continue :outer;
			}
			std.debug.assert(arg.expansion != null);
			for (arg.expansion.?) |*tok| {
				new.append(tok.*)
					catch unreachable;
			}
			continue :outer;
		}
		new.append(token.*)
			catch unreachable;
	}
	if (current.bind.tag == .compile){
		metaprogram(new, outer_binds, mem);
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

pub fn parse_bytecode(mem: *const std.mem.Allocator, tokens: *const Buffer(Token)) ParseError!Buffer(Instruction) {
	var ops = Buffer(Instruction).init(mem.*);
	var token_index: u64 = 0;
	while (token_index < tokens.items.len){
		skip_whitespace(tokens.items, &token_index) catch {
			return ops;
		};
		if (token_index > tokens.items.len){
			std.debug.print("Expected opcode, found end of file\n", .{});
			return ParseError.UnexpectedEOF;
		}
		const token = tokens.items[token_index];
		token_index += 1;
		switch (token.tag){
			.MOV => {
				ops.append(
					Instruction{
						.move=.{
							.dest=try parse_location(mem, tokens, &token_index),
							.src=try parse_location(mem, tokens, &token_index)
						}
					}
				) catch unreachable;
			},
			.ADD, .SUB, .MUL, .DIV => {
				ops.append(
					Instruction{
						.alu=.{
							.tag = token.tag,
							.dest=try parse_location(mem, tokens, &token_index),
							.left=try parse_location(mem, tokens, &token_index),
							.right=try parse_location(mem, tokens, &token_index)
						}
					}
				) catch unreachable;
			},
			.CMP => {
				ops.append(
					Instruction{
						.compare=.{
							.left=try parse_location(mem, tokens, &token_index),
							.right=try parse_location(mem, tokens, &token_index)
						}
					}
				) catch unreachable;
			},
			.JMP, .JLT, .JGT, .JLE, .JGE, .JZ, .JNZ, .JEQ, .JNE => {
				ops.append(
					Instruction{
						.jump=.{
							.tag=token.tag,
							.dest=try parse_location(mem, tokens, &token_index)
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
	return ops;
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
		.IDENTIFIER => {
			token_index.* += 1;
			return Location{
				.literal = hash_global_enum(token)
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
				.immediate = hash_global_enum(token)
			};
		},
		else => {
			std.debug.print("Expected operand, found {s}\n", .{token.text});
			return ParseError.UnexpectedToken;
		}
	}
}

pub fn hash_global_enum(token: Token) u64 {
	if (iden_hashes.get(token.text)) |id| {
		return id;
	}
	iden_hashes.put(token.text, current_iden)
		catch unreachable;
	current_iden += 1;
	return current_iden-1;
}

pub fn show_instructions(instructions: Buffer(Instruction)) void {
	for (instructions.items) |*inst| {
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
}

pub fn show_location(loc: *Location) void {
	switch (loc.*){
		.immediate => {
			std.debug.print("!{} ", .{loc.immediate});
		},
		.literal => {
			std.debug.print("{} ", .{loc.literal});
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

//TODO hoisting to closest token
