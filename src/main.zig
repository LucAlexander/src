const std = @import("std");
const rl = @import("raylib");
const Buffer = std.ArrayList;

const debug = false;

const uid: []const u8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

var iden_hashes = std.StringHashMap(u64).init(std.heap.page_allocator);
var current_iden: u64 = 0;

var persistent = std.StringHashMap(u64).init(std.heap.page_allocator);
var comp_persistent = std.StringHashMap(u64).init(std.heap.page_allocator);
var comp_section = false;

const frame_buffer_w = 320;
const pixel_width = 4;
const word_size = 8;
const frame_buffer_h = 180;

const frame_buffer = frame_buffer_w*frame_buffer_h*pixel_width;
const mem_size = 0x100000;
const main_size = mem_size+frame_buffer;
const register_section = word_size*6;
const start_ip = frame_buffer;
const total_mem_size = frame_buffer+mem_size+register_section;

const VM = struct {
	mem: [total_mem_size]u8,
	words: []align(1) u64,
	half_words: []align(1) u32,
	r0: u64,
	r1: u64,
	r2: u64,
	r3: u64,
	sr: u64,
	ip: u64,
	
	pub fn init() VM {
		return VM{
			.mem=undefined,
			.words=undefined,
			.half_words=undefined,
			.r0=main_size,
			.r1=main_size+1*8,
			.r2=main_size+2*8,
			.r3=main_size+3*8,
			.sr=main_size+4*8,
			.ip=main_size+5*8
		};
	}
};

var vm: VM = VM.init();

var frame_buffer_image = rl.Image{
	.data=&vm.mem[0],
	.width=frame_buffer_w,
	.height=frame_buffer_h,
	.mipmaps=1,
	.format=rl.PixelFormat.uncompressed_r8g8b8a8
};
var frame_buffer_texture:rl.Texture = undefined;

pub fn main() !void {
	std.debug.assert(total_mem_size % 8 == 0);
	comp_persistent.put("mbm", frame_buffer) catch unreachable;
	comp_persistent.put("fbw", frame_buffer_w) catch unreachable;
	comp_persistent.put("fbh", frame_buffer_h) catch unreachable;
	comp_persistent.put("mtp", main_size) catch unreachable;
	persistent.put("mbm", frame_buffer) catch unreachable;
	persistent.put("fbw", frame_buffer_w) catch unreachable;
	persistent.put("fbh", frame_buffer_h) catch unreachable;
	persistent.put("mtp", main_size) catch unreachable;
	const allocator = std.heap.page_allocator;
	var infile = try std.fs.cwd().openFile("red.src", .{});
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
	rl.initWindow(frame_buffer_w, frame_buffer_h, "src");
	frame_buffer_texture = try rl.loadTextureFromImage(frame_buffer_image);
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
		var runtime = VM.init();
		const program_len = parse_bytecode(mem, runtime.mem[frame_buffer..vm.mem.len], token_stream, &index, false) catch |err| {
			std.debug.print("Bytecode Parse Error {}\n", .{err});
			return null;
		};
		vm = runtime;
		if (debug){
			std.debug.print("program length: {}\n", .{program_len});
			std.debug.print("parsed bytecode--------------------\n", .{});
		}
		interpret(start_ip) catch |err| {
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
	LIT,
	EQUAL,
	MOV, MOVL, MOVH,
	ADD, SUB, MUL, DIV, MOD,
	AND, OR, XOR, NOT, COM,
	CMP, JMP,
	JLT, JGT, JLE, JGE, JEQ, JNE,
	INT,
	R0, R1, R2, R3, IP,
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
	token_map.put("movl", .MOVL) catch unreachable;
	token_map.put("movh", .MOVH) catch unreachable;
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

const Instruction = struct {
	data: union(enum) {
		move: struct {
			dest: Location,
			src: Location
		},
		compare: struct {
			left: Location,
			right: Location
		},
		alu: struct {
			dest: Location,
			left: Location,
			right: Location
		},
		jump: struct {
			dest: Location
		},
		interrupt,
	},
	tag: Opcode
};

pub fn parse_bytecode(mem: *const std.mem.Allocator, data: []u8, tokens: *const Buffer(Token), token_index: *u64, comp: bool) ParseError!u64 {
	try retokenize(mem, tokens);
	var labels = std.StringHashMap(u64).init(mem.*);
	const index_save = token_index.*;
	var i: u64 = 0;
	outer: for (0..2) |_| {
		i = 0;
		token_index.* = index_save;
		while (token_index.* < tokens.items.len){
			skip_whitespace(tokens.items, token_index) catch {
				continue :outer;
			};
			if (token_index.* > tokens.items.len){
				std.debug.print("Expected opcode, found end of file\n", .{});
				return ParseError.UnexpectedEOF;
			}
			const token = tokens.items[token_index.*];
			token_index.* += 1;
			var op: ?Instruction = null;
			switch (token.tag){
				.COMP_START => {
					comp_section = true;
					if (debug) {
						std.debug.print("Entering comp segment\n", .{});
					}
					_ = try parse_bytecode(mem, vm.mem[frame_buffer..vm.mem.len], tokens, token_index, true);
					if (debug) {
						std.debug.print("Parsed comp segment\n", .{});
					}
					interpret(start_ip) catch |err| {
						std.debug.print("Runtime Error {}\n", .{err});
						return ParseError.BrokenComptime;
					};
					if (debug) {
						std.debug.print("Exiting comp segment\n", .{});
					}
					comp_section = false;
					continue;
				},
				.COMP_END => {
					if (comp == false){
						continue;
					}
					return i;
				},
				.BIND => {
					skip_whitespace(tokens.items, token_index) catch {
						return i;
					};
					token_index.* += 1;
					skip_whitespace(tokens.items, token_index) catch {
						return i;
					};
					const name = tokens.items[token_index.*];
					token_index.* += 1;
					if (name.tag != .IDENTIFIER){
						std.debug.print("Expected name for transfer bind, found {s}\n", .{name.text});
						return ParseError.UnexpectedToken;
					}
					skip_whitespace(tokens.items, token_index) catch {
						return i;
					};
					if (tokens.items[token_index.*].tag != .EQUAL){
						std.debug.print("Expected = for transfer bind, found {s}\n", .{tokens.items[token_index.*].text});
						return ParseError.UnexpectedToken;
					}
					token_index.* += 1;
					skip_whitespace(tokens.items, token_index) catch {
						return i;
					};
					const is_ip = tokens.items[token_index.*];
					if (is_ip.tag == .IP){
						token_index.* += 1;
						labels.put(name.text, (i/4)+(start_ip/4))
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
						persistent.put(name.text, val)
							catch unreachable;
					}
					else{
						if (debug){
							std.debug.print("persistent put {s} : {}\n", .{name.text, val});
						}
						persistent.put(name.text, val)
							catch unreachable;
					}
					continue;
				},
				.MOV => {
					op = Instruction{
						.tag=.mov_ii,
						.data=.{
							.move=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.src=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.ADD => {
					op = Instruction{
						.tag=.add_iii,
						.data=.{
							.alu=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.SUB => {
					op = Instruction{
						.tag=.sub_iii,
						.data=.{
							.alu=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.MUL => {
					op = Instruction{
						.tag=.mul_iii,
						.data=.{
							.alu=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.DIV => {
					op = Instruction{
						.tag=.div_iii,
						.data=.{
							.alu=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.CMP => {
					op = Instruction{
						.tag=.cmp_ii,
						.data=.{
							.compare=.{
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.JMP => {
					op = Instruction{
						.tag=.jmp_i,
						.data=.{
							.jump=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.JNE => {
					op = Instruction{
						.tag=.jne_i,
						.data=.{
							.jump=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.JEQ => {
					op = Instruction{
						.tag=.jeq_i,
						.data=.{
							.jump=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.JLE => {
					op = Instruction{
						.tag=.jle_i,
						.data=.{
							.jump=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.JLT => {
					op = Instruction{
						.tag=.jlt_i,
						.data=.{
							.jump=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.JGE => {
					op = Instruction{
						.tag=.jge_i,
						.data=.{
							.jump=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.JGT => {
					op = Instruction{
						.tag=.jgt_i,
						.data=.{
							.jump=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.INT => {
					op = Instruction{
						.tag=.int_,
						.data=.{
							.interrupt={}
						}
					};
				},
				else => {
					std.debug.print("Expected opcode, found {s}\n", .{token.text});
					return ParseError.UnexpectedToken;
				}
			}
			std.debug.assert(op != null);
			var inst = op.?;
			const save_i = i;
			switch (inst.data){
				.move => {
					const dest = reduce_location(&inst.data.move.dest);
					const src = reduce_location(&inst.data.move.src);
					reduce_binary_operator(@intFromEnum(inst.tag), data, &i, dest, src);
					store_u32(data, i, 0);
					i += 4;
					write_location(data, &i, dest);
					write_location(data, &i, src);
				},
				.alu => {
					const dest = reduce_location(&inst.data.alu.dest);
					const left = reduce_location(&inst.data.alu.left);
					const right = reduce_location(&inst.data.alu.right);
					reduce_ternary_operator(@intFromEnum(inst.tag), data, &i, dest, left, right);
					write_location(data, &i, dest);
					write_location(data, &i, left);
					write_location(data, &i, right);
				},
				.compare => {
					const left = reduce_location(&inst.data.compare.left);
					const right = reduce_location(&inst.data.compare.right);
					reduce_binary_operator(@intFromEnum(inst.tag), data, &i, left, right);
					store_u32(data, i, 0);
					i += 4;
					write_location(data, &i, left);
					write_location(data, &i, right);
				},
				.jump => {
					const dest = reduce_location(&inst.data.jump.dest);
					if (dest == .immediate){
						store_u32(data, i, @intFromEnum(inst.tag));
						i += 4;
					}
					else if (dest == .literal){
						store_u32(data, i, @intFromEnum(inst.tag)+1);
						i += 4;
					}
					else if (dest == .dereference){
						store_u32(data, i, @intFromEnum(inst.tag)+2);
						i += 4;
					}
					store_u32(data, i, 0);
					i += 4;
					store_u32(data, i, 0);
					i += 4;
					write_location(data, &i, dest);
				},
				.interrupt => {
					store_u32(data, i, @intFromEnum(inst.tag));
					i += 16;
				}
			}
			if (debug){
				std.debug.print("{} : ", .{save_i+start_ip});
				for (save_i..i) |byte_index| {
					std.debug.print("{x:02} ", .{data[byte_index]});
				}
				std.debug.print("\n", .{});
			}
		}
	}
	return i;
}

pub fn parse_location_or_label(mem: *const std.mem.Allocator, tokens: *const Buffer(Token), token_index: *u64, labels: std.StringHashMap(u64), deref: bool) ParseError!Location {
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
	if (deref == false){
		if (token.tag == .OPEN_BRACK){
			token_index.* += 1;
			const reference = try parse_location_or_label(mem, tokens, token_index, labels, true);
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
	}
	switch (token.tag){
		.R0, .R1, .R2, .R3, .IP => {
			token_index.* += 1;
			return Location{
				.register=token.tag
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
		.R0, .R1, .R2, .R3, .IP => {
			token_index.* += 1;
			return Location{
				.register=token.tag
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
	switch (inst.data){
		.move => {
			std.debug.print("mov ", .{});
			show_location(&inst.data.move.dest);
			show_location(&inst.data.move.src);
			std.debug.print("\n", .{});
		},
		.compare => {
			std.debug.print("cmp ", .{});
			show_location(&inst.data.compare.left);
			show_location(&inst.data.compare.right);
			std.debug.print("\n", .{});
		},
		.alu => {
			std.debug.print("alu{} ", .{inst.tag});
			show_location(&inst.data.alu.dest);
			show_location(&inst.data.alu.left);
			show_location(&inst.data.alu.right);
			std.debug.print("\n", .{});
		},
		.jump => {
			std.debug.print("jmp{} ", .{inst.tag});
			show_location(&inst.data.jump.dest);
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

pub fn store_u32(data: []u8, addr: u64, val: u32) void {
	const bytes: [4]u8 = @bitCast(val);
    @memcpy(data[addr .. addr + 4], &bytes);	
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
				.IP => {store_u64(vm.ip, val);},
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
				.IP => {return load_u64(vm.r3);},
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

const Opcode = enum(u8) {
	mov_ii=0, mov_il, mov_id,
	mov_li, mov_ll, mov_ld,
	mov_di, mov_dl, mov_dd,

	add_iii, add_iil, add_iid, add_ili, add_ill, add_ild, add_idi, add_idl, add_idd,
	add_lii, add_lil, add_lid, add_lli, add_lll, add_lld, add_ldi, add_ldl, add_ldd,
	add_dii, add_dil, add_did, add_dli, add_dll, add_dld, add_ddi, add_ddl, add_ddd,
	sub_iii, sub_iil, sub_iid, sub_ili, sub_ill, sub_ild, sub_idi, sub_idl, sub_idd,
	sub_lii, sub_lil, sub_lid, sub_lli, sub_lll, sub_lld, sub_ldi, sub_ldl, sub_ldd,
	sub_dii, sub_dil, sub_did, sub_dli, sub_dll, sub_dld, sub_ddi, sub_ddl, sub_ddd,
	mul_iii, mul_iil, mul_iid, mul_ili, mul_ill, mul_ild, mul_idi, mul_idl, mul_idd,
	mul_lii, mul_lil, mul_lid, mul_lli, mul_lll, mul_lld, mul_ldi, mul_ldl, mul_ldd,
	mul_dii, mul_dil, mul_did, mul_dli, mul_dll, mul_dld, mul_ddi, mul_ddl, mul_ddd,
	div_iii, div_iil, div_iid, div_ili, div_ill, div_ild, div_idi, div_idl, div_idd,
	div_lii, div_lil, div_lid, div_lli, div_lll, div_lld, div_ldi, div_ldl, div_ldd,
	div_dii, div_dil, div_did, div_dli, div_dll, div_dld, div_ddi, div_ddl, div_ddd,

	cmp_ii, cmp_il, cmp_id,
	cmp_li, cmp_ll, cmp_ld,
	cmp_di, cmp_dl, cmp_dd,

	jmp_i, jmp_l, jmp_d,
	jne_i, jne_l, jne_d,
	jeq_i, jeq_l, jeq_d,
	jle_i, jle_l, jle_d,
	jlt_i, jlt_l, jlt_d,
	jge_i, jge_l, jge_d,
	jgt_i, jgt_l, jgt_d,

	int_
};

const OpBytesFn = *const fn (*align(1) u64) RuntimeError!bool;

pub fn interpret(start:u64) RuntimeError!void {
	vm.words = std.mem.bytesAsSlice(u64, vm.mem[0..]);
	vm.half_words = std.mem.bytesAsSlice(u32, vm.mem[0..]);
	const ip = &vm.words[vm.ip/8];
	ip.* = start/4;
	const ops: [148]OpBytesFn = .{
		mov_ii_bytes, mov_il_bytes, mov_id_bytes, mov_li_bytes, mov_ll_bytes, mov_ld_bytes, mov_di_bytes, mov_dl_bytes, mov_dd_bytes,
		add_iii_bytes, add_iil_bytes, add_iid_bytes, add_ili_bytes, add_ill_bytes, add_ild_bytes, add_idi_bytes, add_idl_bytes, add_idd_bytes, add_lii_bytes, add_lil_bytes, add_lid_bytes, add_lli_bytes, add_lll_bytes, add_lld_bytes, add_ldi_bytes, add_ldl_bytes, add_ldd_bytes, add_dii_bytes, add_dil_bytes, add_did_bytes, add_dli_bytes, add_dll_bytes, add_dld_bytes, add_ddi_bytes, add_ddl_bytes, add_ddd_bytes,
		sub_iii_bytes, sub_iil_bytes, sub_iid_bytes, sub_ili_bytes, sub_ill_bytes, sub_ild_bytes, sub_idi_bytes, sub_idl_bytes, sub_idd_bytes, sub_lii_bytes, sub_lil_bytes, sub_lid_bytes, sub_lli_bytes, sub_lll_bytes, sub_lld_bytes, sub_ldi_bytes, sub_ldl_bytes, sub_ldd_bytes, sub_dii_bytes, sub_dil_bytes, sub_did_bytes, sub_dli_bytes, sub_dll_bytes, sub_dld_bytes, sub_ddi_bytes, sub_ddl_bytes, sub_ddd_bytes,
		mul_iii_bytes, mul_iil_bytes, mul_iid_bytes, mul_ili_bytes, mul_ill_bytes, mul_ild_bytes, mul_idi_bytes, mul_idl_bytes, mul_idd_bytes, mul_lii_bytes, mul_lil_bytes, mul_lid_bytes, mul_lli_bytes, mul_lll_bytes, mul_lld_bytes, mul_ldi_bytes, mul_ldl_bytes, mul_ldd_bytes, mul_dii_bytes, mul_dil_bytes, mul_did_bytes, mul_dli_bytes, mul_dll_bytes, mul_dld_bytes, mul_ddi_bytes, mul_ddl_bytes, mul_ddd_bytes,
		div_iii_bytes, div_iil_bytes, div_iid_bytes, div_ili_bytes, div_ill_bytes, div_ild_bytes, div_idi_bytes, div_idl_bytes, div_idd_bytes, div_lii_bytes, div_lil_bytes, div_lid_bytes, div_lli_bytes, div_lll_bytes, div_lld_bytes, div_ldi_bytes, div_ldl_bytes, div_ldd_bytes, div_dii_bytes, div_dil_bytes, div_did_bytes, div_dli_bytes, div_dll_bytes, div_dld_bytes, div_ddi_bytes, div_ddl_bytes, div_ddd_bytes,
		cmp_ii_bytes, cmp_il_bytes, cmp_id_bytes, cmp_li_bytes, cmp_ll_bytes, cmp_ld_bytes, cmp_di_bytes, cmp_dl_bytes, cmp_dd_bytes,
		jmp_i_bytes, jmp_l_bytes, jmp_d_bytes, jne_i_bytes, jne_l_bytes, jne_d_bytes, jeq_i_bytes, jeq_l_bytes, jeq_d_bytes, jle_i_bytes, jle_l_bytes, jle_d_bytes, jlt_i_bytes, jlt_l_bytes, jlt_d_bytes, jge_i_bytes, jge_l_bytes, jge_d_bytes, jgt_i_bytes, jgt_l_bytes, jgt_d_bytes,
		int_bytes
	};
	var running = true;
	while (running) {
		if (debug){
			std.debug.print("{}: {x:02} ...\n", .{ip.*, vm.mem[ip.*]});
			std.debug.print("r0: {}\n", .{load_u64(vm.r0)});
			std.debug.print("r1: {}\n", .{load_u64(vm.r1)});
			std.debug.print("r2: {}\n", .{load_u64(vm.r2)});
			std.debug.print("r3: {}\n", .{load_u64(vm.r3)});
			std.debug.print("sr: {}\n", .{load_u64(vm.sr)});
			var stdin = std.io.getStdIn().reader();
			var buffer: [1]u8 = undefined;
			_ = stdin.read(&buffer) catch unreachable;
		}
		running = try ops[vm.half_words[ip.*]](ip);
	}
}

pub fn mov_ii_bytes(ip: *align(1) u64) RuntimeError!bool{
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+2];
	const src_name = vm.half_words[p+3];
	const src = load_u64(src_name);
	store_u64(dest, src);
	return true;
}

pub fn mov_il_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+2];
	const src = vm.half_words[p+3];
	store_u64(dest, src);
	return true;
}

pub fn mov_id_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+2];
	const src_name = vm.half_words[p+3];
	const src_imm = load_u64(src_name);
	const src = load_u64(src_imm);
	store_u64(dest, src);
	return true;
}

pub fn mov_li_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+2];
	const src_name = vm.half_words[p+3];
	const src = load_u64(src_name);
	store_u64(dest, src);
	return true;
}

pub fn mov_ll_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+2];
	const src = vm.half_words[p+3];
	store_u64(dest, src);
	return true;
}

pub fn mov_ld_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+2];
	const src_name = vm.half_words[p+3];
	const src_imm = load_u64(src_name);
	const src = load_u64(src_imm);
	store_u64(dest, src);
	return true;
}

pub fn mov_di_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+2];
	const dest = load_u64(dest_name);
	const src_name = vm.half_words[p+3];
	const src = load_u64(src_name);
	store_u64(dest, src);
	return true;
}

pub fn mov_dl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+2];
	const dest = load_u64(dest_name);
	const src = vm.half_words[p+3];
	store_u64(dest, src);
	return true;
}

pub fn mov_dd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+2];
	const dest = load_u64(dest_name);
	const src_name = vm.half_words[p+3];
	const src_imm = load_u64(src_name);
	const src = load_u64(src_imm);
	store_u64(dest, src);
	return true;
}

pub fn add_iii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b = load_u64(b_name);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_iil_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a = load_u64(a_name);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_iid_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_ili_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b = load_u64(b_name);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_ill_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_ild_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_idi_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_name);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_idl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_idd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_imm);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_lii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b = load_u64(b_name);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_lil_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a = load_u64(a_name);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_lid_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_lli_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b = load_u64(b_name);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_lll_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_lld_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_ldi_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_name);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_ldl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_ldd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_imm);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_dii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b = load_u64(b_name);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_dil_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a = load_u64(a_name);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_did_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_dli_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b = load_u64(b_name);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_dll_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_dld_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_ddi_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_name);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_ddl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn add_ddd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_imm);
	const c = a + b;
	store_u64(dest, c);
	return true;
}

pub fn sub_iii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b = load_u64(b_name);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_iil_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a = load_u64(a_name);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_iid_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_ili_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b = load_u64(b_name);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_ill_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_ild_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_idi_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_name);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_idl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_idd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_imm);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_lii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b = load_u64(b_name);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_lil_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a = load_u64(a_name);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_lid_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_lli_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b = load_u64(b_name);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_lll_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_lld_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_ldi_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_name);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_ldl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_ldd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_imm);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_dii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b = load_u64(b_name);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_dil_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a = load_u64(a_name);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_did_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_dli_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b = load_u64(b_name);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_dll_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_dld_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_ddi_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_name);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_ddl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn sub_ddd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_imm);
	const c = a - b;
	store_u64(dest, c);
	return true;
}

pub fn mul_iii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b = load_u64(b_name);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_iil_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a = load_u64(a_name);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_iid_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_ili_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b = load_u64(b_name);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_ill_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_ild_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_idi_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_name);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_idl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_idd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_imm);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_lii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b = load_u64(b_name);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_lil_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a = load_u64(a_name);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_lid_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_lli_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b = load_u64(b_name);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_lll_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_lld_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_ldi_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_name);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_ldl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_ldd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_imm);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_dii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b = load_u64(b_name);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_dil_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a = load_u64(a_name);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_did_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_dli_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b = load_u64(b_name);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_dll_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_dld_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_ddi_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_name);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_ddl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn mul_ddd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_imm);
	const c = a * b;
	store_u64(dest, c);
	return true;
}

pub fn div_iii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b = load_u64(b_name);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_iil_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a = load_u64(a_name);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_iid_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_ili_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b = load_u64(b_name);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_ill_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_ild_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_idi_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_name);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_idl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_idd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_imm);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_lii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b = load_u64(b_name);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_lil_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a = load_u64(a_name);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_lid_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_lli_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b = load_u64(b_name);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_lll_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_lld_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_ldi_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_name);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_ldl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_ldd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest = vm.half_words[p+1];
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_imm);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_dii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b = load_u64(b_name);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_dil_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a = load_u64(a_name);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_did_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_dli_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b = load_u64(b_name);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_dll_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_dld_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const b_imm = load_u64(b_name);
	const b = load_u64(b_imm);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_ddi_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_name);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_ddl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const a = load_u64(a_imm);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn div_ddd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const p = ip.*;
	ip.* += 4;
	const dest_name = vm.half_words[p+1];
	const dest = load_u64(dest_name);
	const a_name = vm.half_words[p+2];
	const b_name = vm.half_words[p+3];
	const a_imm = load_u64(a_name);
	const b_imm = load_u64(b_name);
	const a = load_u64(a_imm);
	const b = load_u64(b_imm);
	const c = a / b;
	store_u64(dest, c);
	return true;
}

pub fn cmp_ii_bytes(ip: *align(1) u64) RuntimeError!bool {
	const left_name = vm.half_words[ip.*+2];
	const right_name = vm.half_words[ip.*+3];
	const left = load_u64(left_name);
	const right = load_u64(right_name);
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 4;
	return true;
}

pub fn cmp_il_bytes(ip: *align(1) u64) RuntimeError!bool {
	const left = vm.half_words[ip.*+2];
	const right_name = vm.half_words[ip.*+3];
	const right = load_u64(right_name);
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 4;
	return true;
}

pub fn cmp_id_bytes(ip: *align(1) u64) RuntimeError!bool {
	const left_name = vm.half_words[ip.*+2];
	const left = load_u64(left_name);
	const right_name = vm.half_words[ip.*+3];
	const right_imm = load_u64(right_name);
	const right = load_u64(right_imm);
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 4;
	return true;
}

pub fn cmp_li_bytes(ip: *align(1) u64) RuntimeError!bool {
	const left = vm.half_words[ip.*+2];
	const right_name = vm.half_words[ip.*+3];
	const right = load_u64(right_name);
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 4;
	return true;
}

pub fn cmp_ll_bytes(ip: *align(1) u64) RuntimeError!bool {
	const left = vm.half_words[ip.*+2];
	const right = vm.half_words[ip.*+3];
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 4;
	return true;
}

pub fn cmp_ld_bytes(ip: *align(1) u64) RuntimeError!bool {
	const left = vm.half_words[ip.*+2];
	const right_name = vm.half_words[ip.*+3];
	const right_imm = load_u64(right_name);
	const right = load_u64(right_imm);
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 4;
	return true;
}

pub fn cmp_di_bytes(ip: *align(1) u64) RuntimeError!bool {
	const left_name = vm.half_words[ip.*+2];
	const left_imm = load_u64(left_name);
	const left = load_u64(left_imm);
	const right_name = vm.half_words[ip.*+3];
	const right = load_u64(right_name);
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 4;
	return true;
}

pub fn cmp_dl_bytes(ip: *align(1) u64) RuntimeError!bool {
	const left_name = vm.half_words[ip.*+2];
	const left_imm = load_u64(left_name);
	const left = load_u64(left_imm);
	const right = vm.half_words[ip.*+3];
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 4;
	return true;
}

pub fn cmp_dd_bytes(ip: *align(1) u64) RuntimeError!bool {
	const left_name = vm.half_words[ip.*+2];
	const left_imm = load_u64(left_name);
	const left = load_u64(left_imm);
	const right_name = vm.half_words[ip.*+3];
	const right_imm = load_u64(right_name);
	const right = load_u64(right_imm);
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 4;
	return true;
}

pub fn jmp_i_bytes(ip: *align(1) u64) RuntimeError!bool {
	const label = vm.half_words[ip.*+3];
	const dest = load_u64(label);
	ip.* = dest;
	return true;
}

pub fn jmp_l_bytes(ip: *align(1) u64) RuntimeError!bool {
	const label = vm.half_words[ip.*+3];
	ip.* = label;
	return true;
}

pub fn jmp_d_bytes(ip: *align(1) u64) RuntimeError!bool {
	const label = vm.half_words[ip.*+3];
	const label_imm = load_u64(label);
	const dest = load_u64(label_imm);
	ip.* = dest;
	return true;
}

pub fn jne_i_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] != 0){
		const label = vm.half_words[ip.*+3];
		const dest = load_u64(label);
		ip.* = dest;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jne_l_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] != 0){
		const label = vm.half_words[ip.*+3];
		ip.* = label;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jne_d_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] != 0){
		const label = vm.half_words[ip.*+3];
		const dest_imm = load_u64(label);
		const dest = load_u64(dest_imm);
		ip.* = dest;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jeq_i_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] == 0){
		const label = vm.half_words[ip.*+3];
		const dest = load_u64(label);
		ip.* = dest;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jeq_l_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] == 0){
		const label = vm.half_words[ip.*+3];
		ip.* = label;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jeq_d_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] == 0){
		const label = vm.half_words[ip.*+3];
		const dest_imm = load_u64(label);
		const dest = load_u64(dest_imm);
		ip.* = dest;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jgt_i_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] == 1){
		const label = vm.half_words[ip.*+3];
		const dest = load_u64(label);
		ip.* = dest;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jgt_l_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] == 1){
		const label = vm.half_words[ip.*+3];
		ip.* = label;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jgt_d_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] == 1){
		const label = vm.half_words[ip.*+3];
		const dest_imm = load_u64(label);
		const dest = load_u64(dest_imm);
		ip.* = dest;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jge_i_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] != 2){
		const label = vm.half_words[ip.*+3];
		const dest = load_u64(label);
		ip.* = dest;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jge_l_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] != 2){
		const label = vm.half_words[ip.*+3];
		ip.* = label;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jge_d_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] != 2){
		const label = vm.half_words[ip.*+3];
		const dest_imm = load_u64(label);
		const dest = load_u64(dest_imm);
		ip.* = dest;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jlt_i_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] == 2){
		const label = vm.half_words[ip.*+3];
		const dest = load_u64(label);
		ip.* = dest;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jlt_l_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] == 2){
		const label = vm.half_words[ip.*+3];
		ip.* = label;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jlt_d_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] == 2){
		const label = vm.half_words[ip.*+3];
		const dest_imm = load_u64(label);
		const dest = load_u64(dest_imm);
		ip.* = dest;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jle_i_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] != 1){
		const label = vm.half_words[ip.*+3];
		const dest = load_u64(label);
		ip.* = dest;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jle_l_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] != 1){
		const label = vm.half_words[ip.*+3];
		ip.* = label;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn jle_d_bytes(ip: *align(1) u64) RuntimeError!bool {
	if (vm.mem[vm.sr] != 1){
		const label = vm.half_words[ip.*+3];
		const dest_imm = load_u64(label);
		const dest = load_u64(dest_imm);
		ip.* = dest;
	}
	else {
		ip.* += 4;
	}
	return true;
}

pub fn int_bytes(ip: *align(1) u64) RuntimeError!bool {
	ip.* += 4;
	if (vm.mem[vm.r0] == 0){
		rl.updateTexture(frame_buffer_texture, &vm.mem[0]);
		rl.beginDrawing();
		rl.drawTexture(frame_buffer_texture, 0, 0, .white);
		rl.endDrawing();
		const fps = rl.getFPS();
		std.debug.print("{}\n", .{fps});
		return true;
	}
	if (vm.mem[vm.r0] == 1){
		return false;
	}
	if (vm.mem[vm.r0] == 2){
		std.debug.print("{}\n", .{vm.mem[vm.r1]});
		return true;
	}
	return true;
}

pub fn reduce_location(loc: *Location) Location {
	switch (loc.*){
		.register => {
			switch (loc.register){
				.R0 => {
					loc.* = Location{
						.immediate = vm.r0
					};
				},
				.R1 => {
					loc.* = Location{
						.immediate = vm.r1
					};
				},
				.R2 => {
					loc.* = Location{
						.immediate = vm.r2
					};
				},
				.R3 => {
					loc.* = Location{
						.immediate = vm.r3
					};
				},
				.IP => {
					loc.* = Location{
						.immediate = vm.ip
					};
				},
				else => {unreachable;}
			}
		},
		.dereference => {
			_ = reduce_location(loc.dereference);
		},
		else => { }
	}
	return loc.*;
}

pub fn reduce_ternary_operator(seed: u8, data: []u8, i: *u64, a: Location, b: Location, c: Location) void {
	if (a == .immediate){
		reduce_binary_operator(seed, data, i, b, c);
	}
	else if (a == .literal){
		reduce_binary_operator(seed+9, data, i, b, c);
	}
	else if (a == .dereference){
		reduce_binary_operator(seed+18, data, i, b, c);
	}
}

pub fn reduce_binary_operator(seed: u8, data: []u8, i: *u64, a: Location, b: Location) void {
	if (a == .immediate){
		if (b == .immediate){
			store_u32(data, i.*, seed);
			i.* += 4;
		}
		else if (b == .literal){
			store_u32(data, i.*, seed+1);
			i.* += 4;
		}
		else if (b == .dereference){
			store_u32(data, i.*, seed+2);
			i.* += 4;
		}
	}
	else if (a == .literal){
		if (b == .immediate){
			store_u32(data, i.*, seed+3);
			i.* += 4;
		}
		else if (b == .literal){
			store_u32(data, i.*, seed+4);
			i.* += 4;
		}
		else if (b == .dereference){
			store_u32(data, i.*, seed+5);
			i.* += 4;
		}
	}
	else if (a == .dereference){
		if (b == .immediate){
			store_u32(data, i.*, seed+6);
			i.* += 4;
		}
		else if (b == .literal){
			store_u32(data, i.*, seed+7);
			i.* += 4;
		}
		else if (b == .dereference){
			store_u32(data, i.*, seed+8);
			i.* += 4;
		}
	}
}

pub fn write_location(data: []u8, i: *u64, loc: Location) void {
	switch(loc){
		.immediate => {
			store_u32(data, i.*, @truncate(loc.immediate));
			i.* += 4;
		},
		.literal => {
			store_u32(data, i.*, @truncate(loc.literal));
			i.* += 4;
		},
		.dereference => {
			write_location(data, i, loc.dereference.*);
		},
		.register => {
			unreachable;
		}
	}
}

//TODO more instructions
	//alu shifts
	//logical operators
	//mov instructions
//TODO emulated hardware components of the virtual computer
//TODO metaprogram parse operation as an interrupt
	// interrupts: write n to file, read n from file, get input from keyboard/mouse, send info to screen
//TODO think about debugging infrastructure
//TODO introduce propper debugger state

//TODO switch ip to 16 byte

//TODO separate comptime and runbind from parse, to make sure that the tool can be used with other languages while still using comptime and runbinds, use a different setting
//TODO cli
//TODO machine config
