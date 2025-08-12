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
	var token_index: u64 = 0;
	program.text=&text;
	while (!done){
		program.text.clearRetainingCapacity();
		token_index = 0;
		done = parse(&mem, token_stream, &program, &token_index) catch |err| {
			std.debug.print("Parse Error {}\n", .{err});
			report_error(token_stream, token_index);
			return;
		};
		show_program(program);
		if (done){
			break;
		}
		token_stream = apply_binds(&mem, &auxil, &text, &program);
	}
}

const ParseError = error {
	PrematureEnd,
	UnexpectedToken,
	UnexpectedEOf
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
	text: Buffer(Token)
};

const AppliedBind = struct {
	bind: *Bind,
	expansions: Buffer(?[]Token),
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

pub fn parse(mem: *const std.mem.Allocator, tokens: *Buffer(Token), program: *ProgramText, token_index: *u64) !bool {
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
	return bind;
}

pub fn skip_whitespace(tokens: []Token, token_index: *u64) !void {
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
				.alternate=Buffer(Buffer(*Arg)).init(mem.*)
			}
		};
		var inner = Buffer(*Arg).init(mem.*);
		const atloc = mem.create(Arg);
		const idenloc = mem.create(Arg);
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
	if (tokens[token_index.*].tag == .IDENTIFIER){
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
		std.debug.print("Expected either - ? or + to head non keyword argument, found {s}\n", .{tokens[token_index.*].text});
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

pub fn report_error(token_stream: *Buffer(Token), token_index: u64) void{
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
	for (program.binds.items) |bind| {
		std.debug.print("{}: precedence {}\nargs:\n", .{bind.tag, bind.precedence});
		for (bind.args.items) |arg| {
			show_arg(arg);
			std.debug.print("\n", .{});
		}
		std.debug.print("expansion:\n", .{});
		show_tokens(bind.text);
	}
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
				for (list.items) |inner| {
					std.debug.print("| ", .{});
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
	ExclusionPresent
};

//TODO make these systems first try to match macros, then instructions, then tokens
pub fn apply_rule(rule: *Arg, tokens: []Token, token_index: u64) PatternError!?[]Token {
	switch (rule.tag){
		.unique => {
			std.debug.assert(@tagOf(rule.pattern) == Pattern.alternate);
			return apply_pattern(&rule.pattern, tokens, token_index);
		},
		.inclusion => {
			return apply_pattern(&rule.pattern, tokens, token_index);
		},
		.exclusion => {
			apply_pattern(&rule.pattern, tokens, token_index) catch {
				return null;
			};
			return PatternError.ExclusionPresent;
		},
		.optional => {
			return apply_pattern(&rule.pattern, tokens, token_index) catch {
				return null;
			};
		}
	}
	unreachable;
}

pub fn apply_pattern(pattern: *Pattern, tokens: []Token, token_index: u64) PatternError![]Token {
	switch (pattern){
		.token => {
			return tokens[token_index..token_index+1];
		},
		.keyword => {
			if (token_equal(&tokens[tokens_index.*], &pattern.keyword)){
				return tokens[token_index..token_index+1];
			}
			return PatternError.MissingKeyword;
		},
		.alternate => {
			blk: for (pattern.alternate.items) |*list| {
				var temp_index = token_index;
				for (list.items) |arg| {
					const sequence = apply_rule(arg, tokens, temp_index) catch {
						continue :blk;
					};
					temp_index += 1;
				}
				return tokens[token_index..temp_index];
			}
			return PatternError.ExhaustedAlternate;
		},
		.group => {
			const open_sequence = try apply_rule(pattern.group.open, tokens, token_index);
			var temp_index = token_index + open_sequence.len;
			while (temp_index < tokens.len){
				const close_sequence = apply_rule(pattern.group.close, tokens, temp_index) catch {
					temp_index += 1;
					continue;
				};
				temp_index += close_sequence.len;
				break;
			}
			return tokens[token_index..temp_index];
		},
		.variadic => {
			std.debug.assert(pattern.variadic.separator != null);
			var temp_index:u64 = token_index;
			var times:u64 = 0;
			var matches = true;
			while (matches){
				var save_index = temp_index;
				for (pattern.variadic.members.items) |arg| {
					const sequence = apply_rule(arg, tokens, temp_index) catch |err| {
						if (times == 0){
							return err;
						}
						return tokens[token_index..save_index];
					};
					token_index += sequence.len;
				}
				const sep_sequence = apply_rule(pattern.variadic.separator, tokens, temp_index) catch {
					return tokens[token_index..temp_index];
				};
				times = 1;
				temp_index += sep_sequence.len;
			}
		}
	}
	unreachable;
}

pub fn apply_bind(mem: *const std.mem.Allocator, bind: *Bind, tokens: []Token, token_index: *u64) ?AppliedBind {
	const save_index = token_index.*;
	var list = Buffer([]Token).init(mem.*);
	for (bind.args) |*arg| {
		const sequence = apply_rule(arg, tokens, token_index.*) catch {
			token_index.* = save_index;
			return null;
		}
		if (sequence) |seq| {
			token_index.* += seq.len;
		}
		list.append(sequence)
			catch unreachable;
	}
	return AppliedBind{
		.bind = bind,
		.expansions=list,
		.start_index = save_index,
		.end_index = token_index.*
	};
}

pub fn block_binds(mem: *const std.mem.Allocator, program: *ProgramText, precedence: u64) Buffer(AppliedBind) {
	var buffer = Buffer(AppliedBind).init(mem.*);
	var i: u64 = 0;
	while (i < program.text.items.len){
		for (program.binds.items) |*bind| {
			if (bind.precedence != precedence){
				continue;
			}
			if (apply_bind(mem, bind, program.text, items, &i)) |applied| {
				buffer.append(applied)
					catch unreachable;
			}
		}
	}
	return buffer;
}

pub fn apply_binds(mem: *const std.mem.Allocator, txt: *Buffer(Token), aux: *Buffer(Token), program: *ProgramText) *Buffer(Token) {
	var precedence: u64 = blk: {
		var max: u64 = '0';
		for (programText.binds.items) |*bind| {
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
		var new.clearRetainingCapacity();
		if (blocks.items.len == 0){
			continue;
		}
		var i: u64 = 0;
		var token_index = 0;
		while (i < blocks.items.len-1){
			const current = blocks.items[i];
			const next = blocks.items[i+1];
			while (token_index < current.start_index){
				new.append(program.text[token_index])
					catch unreachable;
				token_index += 1;
			}
			token_index = current.end_index + 1;
			var adjust = false;
			if (current.end_index > next.start_index and current.end_index < next.end_index){
				adjust = true;
			}
			rewrite: {
				outer: for (current.bind.text.items) |*token| {
					for (current.bind.args.items, 0..) |*arg, index| {
						if (arg.tag == .optional){
							if (current.replacements.items[index] != null){
								if (@tagOf(arg.pattern) == Pattern.keyword){
									for (current.replacements.items[index]) |*token| {
										new.append(token.*);
									}
									continue :outer;
								}
							}
						}
						if (arg.tag == .inclusion){
							if (@tagOf(arg.pattern) == Pattern.keyword){
								std.debug.assert(current.replacements.items[index] != null);
								for (current.replacements.items[index]) |*token| {
									new.append(token.*);
								}
								continue :outer;
							}
							else if (@tagOf(arg.pattern) == Pattern.variadic){
								//TODO expand loop
								continue :outer;
							}
						}
						//TODO do we have to do anythingh with iden, create unique identifier and replace directly, we'll leave without for now I gues and come back to it
					}
					new.append(token.*);
				}
			};
			if (adjust == true){
				reparse = true;
				while (token_index < program.text.len){
					new.append(program.te[token_index])
						catch unreachable;
					token_index += 1;
				}
				break;
			}
			i += 1;
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
	}
	const stream = program.text;
	program.text = new
	return stream;
}

pub fn token_equal(a: *Token, b: *Token) bool {
	if (a.tag != b.tag){
		return false;
	}
	return a.text == b.text;
}
