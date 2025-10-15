const std = @import("std");
const rl = @import("raylib");
const Buffer = std.ArrayList;

const debug = true;

var uid: []const u8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

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
	push_builtin_constants();
	std.debug.assert(total_mem_size % 8 == 0);
	const allocator = std.heap.page_allocator;
	const args = try std.process.argsAlloc(allocator);
	switch (args.len){
		2 => {
			const filename = args[1];
			if (std.mem.eql(u8, filename, "-h")){
				std.debug.print("Help Menu\n", .{});
				std.debug.print("    src -h                    : show this message\n", .{});
				std.debug.print("    src infile.src            : compile and run src program\n", .{});
				std.debug.print("    src infile.src -o out.bin : compile src program to binary\n", .{});
				std.debug.print("    src infile.src -p out.out : compile src program as a plugin\n", .{});
				std.debug.print("    src -i infile.bin         : run compiled src program\n", .{});
				return;
			}
			compile_and_run(filename);
		},
		3 => {
			const i = args[1];
			if (!std.mem.eql(u8, i, "-i")){
				std.debug.print("Expected arg 1 as -i for specifying input binary file, found {s}\n", .{i});
			}
			const filename = args[2];
			run_file(filename);
		},
		4 => {
			const infile = args[1];
			const option = args[2];
			const outfile = args[3];
			if (std.mem.eql(u8, option, "-p")){
				compile_and_write(infile, outfile, true);
				return;
			}
			if (!std.mem.eql(u8, option, "-o")){
				std.debug.print("Expected arg 2 as -o for specifying output binary file, found {s}\n", .{option});
				return;
			}
			compile_and_write(infile, outfile, false);
		},
		1 => {
			std.debug.print("Provide args, provide -h for help\n", .{});
		},
		else => {
			std.debug.print("Incorrect number of args, provide -h for help\n", .{});
		}
	}
}

pub fn push_builtin_constants() void {
	comp_persistent.put("mbm", frame_buffer) catch unreachable;
	comp_persistent.put("fbw", frame_buffer_w) catch unreachable;
	comp_persistent.put("fbh", frame_buffer_h) catch unreachable;
	comp_persistent.put("mtp", main_size) catch unreachable;
	comp_persistent.put("SRC_MOUSE_LEFT", @intFromEnum(rl.MouseButton.left)) catch unreachable;
	comp_persistent.put("SRC_MOUSE_RIGHT", @intFromEnum(rl.MouseButton.right)) catch unreachable;
	comp_persistent.put("SRC_MOUSE_MIDDLE", @intFromEnum(rl.MouseButton.middle)) catch unreachable;
	comp_persistent.put("SRC_Q", @intFromEnum(rl.KeyboardKey.q)) catch unreachable;
	comp_persistent.put("SRC_W", @intFromEnum(rl.KeyboardKey.w)) catch unreachable;
	comp_persistent.put("SRC_E", @intFromEnum(rl.KeyboardKey.e)) catch unreachable;
	comp_persistent.put("SRC_R", @intFromEnum(rl.KeyboardKey.r)) catch unreachable;
	comp_persistent.put("SRC_T", @intFromEnum(rl.KeyboardKey.t)) catch unreachable;
	comp_persistent.put("SRC_Y", @intFromEnum(rl.KeyboardKey.y)) catch unreachable;
	comp_persistent.put("SRC_U", @intFromEnum(rl.KeyboardKey.u)) catch unreachable;
	comp_persistent.put("SRC_I", @intFromEnum(rl.KeyboardKey.i)) catch unreachable;
	comp_persistent.put("SRC_O", @intFromEnum(rl.KeyboardKey.o)) catch unreachable;
	comp_persistent.put("SRC_P", @intFromEnum(rl.KeyboardKey.p)) catch unreachable;
	comp_persistent.put("SRC_A", @intFromEnum(rl.KeyboardKey.a)) catch unreachable;
	comp_persistent.put("SRC_S", @intFromEnum(rl.KeyboardKey.s)) catch unreachable;
	comp_persistent.put("SRC_D", @intFromEnum(rl.KeyboardKey.d)) catch unreachable;
	comp_persistent.put("SRC_F", @intFromEnum(rl.KeyboardKey.f)) catch unreachable;
	comp_persistent.put("SRC_G", @intFromEnum(rl.KeyboardKey.g)) catch unreachable;
	comp_persistent.put("SRC_H", @intFromEnum(rl.KeyboardKey.h)) catch unreachable;
	comp_persistent.put("SRC_J", @intFromEnum(rl.KeyboardKey.j)) catch unreachable;
	comp_persistent.put("SRC_K", @intFromEnum(rl.KeyboardKey.k)) catch unreachable;
	comp_persistent.put("SRC_L", @intFromEnum(rl.KeyboardKey.l)) catch unreachable;
	comp_persistent.put("SRC_Z", @intFromEnum(rl.KeyboardKey.z)) catch unreachable;
	comp_persistent.put("SRC_X", @intFromEnum(rl.KeyboardKey.x)) catch unreachable;
	comp_persistent.put("SRC_C", @intFromEnum(rl.KeyboardKey.c)) catch unreachable;
	comp_persistent.put("SRC_V", @intFromEnum(rl.KeyboardKey.v)) catch unreachable;
	comp_persistent.put("SRC_B", @intFromEnum(rl.KeyboardKey.b)) catch unreachable;
	comp_persistent.put("SRC_N", @intFromEnum(rl.KeyboardKey.n)) catch unreachable;
	comp_persistent.put("SRC_M", @intFromEnum(rl.KeyboardKey.m)) catch unreachable;
	comp_persistent.put("SRC_LEFT", @intFromEnum(rl.KeyboardKey.left)) catch unreachable;
	comp_persistent.put("SRC_RIGHT", @intFromEnum(rl.KeyboardKey.right)) catch unreachable;
	comp_persistent.put("SRC_UP", @intFromEnum(rl.KeyboardKey.up)) catch unreachable;
	comp_persistent.put("SRC_DOWN", @intFromEnum(rl.KeyboardKey.down)) catch unreachable;
	comp_persistent.put("SRC_SPACE", @intFromEnum(rl.KeyboardKey.space)) catch unreachable;
	persistent.put("mbm", frame_buffer) catch unreachable;
	persistent.put("fbw", frame_buffer_w) catch unreachable;
	persistent.put("fbh", frame_buffer_h) catch unreachable;
	persistent.put("mtp", main_size) catch unreachable;
	persistent.put("SRC_MOUSE_LEFT", @intFromEnum(rl.MouseButton.left)) catch unreachable;
	persistent.put("SRC_MOUSE_RIGHT", @intFromEnum(rl.MouseButton.right)) catch unreachable;
	persistent.put("SRC_MOUSE_MIDDLE", @intFromEnum(rl.MouseButton.middle)) catch unreachable;
	persistent.put("SRC_Q", @intFromEnum(rl.KeyboardKey.q)) catch unreachable;
	persistent.put("SRC_W", @intFromEnum(rl.KeyboardKey.w)) catch unreachable;
	persistent.put("SRC_E", @intFromEnum(rl.KeyboardKey.e)) catch unreachable;
	persistent.put("SRC_R", @intFromEnum(rl.KeyboardKey.r)) catch unreachable;
	persistent.put("SRC_T", @intFromEnum(rl.KeyboardKey.t)) catch unreachable;
	persistent.put("SRC_Y", @intFromEnum(rl.KeyboardKey.y)) catch unreachable;
	persistent.put("SRC_U", @intFromEnum(rl.KeyboardKey.u)) catch unreachable;
	persistent.put("SRC_I", @intFromEnum(rl.KeyboardKey.i)) catch unreachable;
	persistent.put("SRC_O", @intFromEnum(rl.KeyboardKey.o)) catch unreachable;
	persistent.put("SRC_P", @intFromEnum(rl.KeyboardKey.p)) catch unreachable;
	persistent.put("SRC_A", @intFromEnum(rl.KeyboardKey.a)) catch unreachable;
	persistent.put("SRC_S", @intFromEnum(rl.KeyboardKey.s)) catch unreachable;
	persistent.put("SRC_D", @intFromEnum(rl.KeyboardKey.d)) catch unreachable;
	persistent.put("SRC_F", @intFromEnum(rl.KeyboardKey.f)) catch unreachable;
	persistent.put("SRC_G", @intFromEnum(rl.KeyboardKey.g)) catch unreachable;
	persistent.put("SRC_H", @intFromEnum(rl.KeyboardKey.h)) catch unreachable;
	persistent.put("SRC_J", @intFromEnum(rl.KeyboardKey.j)) catch unreachable;
	persistent.put("SRC_K", @intFromEnum(rl.KeyboardKey.k)) catch unreachable;
	persistent.put("SRC_L", @intFromEnum(rl.KeyboardKey.l)) catch unreachable;
	persistent.put("SRC_Z", @intFromEnum(rl.KeyboardKey.z)) catch unreachable;
	persistent.put("SRC_X", @intFromEnum(rl.KeyboardKey.x)) catch unreachable;
	persistent.put("SRC_C", @intFromEnum(rl.KeyboardKey.c)) catch unreachable;
	persistent.put("SRC_V", @intFromEnum(rl.KeyboardKey.v)) catch unreachable;
	persistent.put("SRC_B", @intFromEnum(rl.KeyboardKey.b)) catch unreachable;
	persistent.put("SRC_N", @intFromEnum(rl.KeyboardKey.n)) catch unreachable;
	persistent.put("SRC_M", @intFromEnum(rl.KeyboardKey.m)) catch unreachable;
	persistent.put("SRC_LEFT", @intFromEnum(rl.KeyboardKey.left)) catch unreachable;
	persistent.put("SRC_RIGHT", @intFromEnum(rl.KeyboardKey.right)) catch unreachable;
	persistent.put("SRC_UP", @intFromEnum(rl.KeyboardKey.up)) catch unreachable;
	persistent.put("SRC_DOWN", @intFromEnum(rl.KeyboardKey.down)) catch unreachable;
	persistent.put("SRC_SPACE", @intFromEnum(rl.KeyboardKey.space)) catch unreachable;

}

pub fn compile_and_run(filename: []u8) void {
	const allocator = std.heap.page_allocator;
	var infile = std.fs.cwd().openFile(filename, .{}) catch {
		std.debug.print("File not found: {s}\n", .{filename});
		return;
	};
	defer infile.close();
	const stat = infile.stat() catch {
		std.debug.print("Errored file stat: {s}\n", .{filename});
		return;
	};
	const contents = infile.readToEndAlloc(allocator, stat.size+1) catch {
		std.debug.print("Error reading file: {s}\n", .{filename});
		return;
	};
	defer allocator.free(contents);
	var main_mem = std.heap.ArenaAllocator.init(allocator);
	defer main_mem.deinit();
	const mem = main_mem.allocator();
	var tokens = tokenize(&mem, contents);
	show_tokens(tokens);
	if (debug){
		std.debug.print("initial------------------------------\n", .{});
	}
	rl.initWindow(frame_buffer_w, frame_buffer_h, "src");
	frame_buffer_texture = rl.loadTextureFromImage(frame_buffer_image) catch {
		std.debug.print("Error creating texture\n", .{});
		return;
	};
	_ = metaprogram(&tokens, &mem, true, null);
}

pub fn compile_and_write(infilename: []u8, outfilename: []u8, plugin: bool) void {
	const allocator = std.heap.page_allocator;
	var infile = std.fs.cwd().openFile(infilename, .{}) catch {
		std.debug.print("File not found: {s}\n", .{infilename});
		return;
	};
	defer infile.close();
	const stat = infile.stat() catch {
		std.debug.print("Errored file stat: {s}\n", .{infilename});
		return;
	};
	const contents = infile.readToEndAlloc(allocator, stat.size+1) catch {
		std.debug.print("Error reading file: {s}\n", .{infilename});
		return;
	};
	defer allocator.free(contents);
	var main_mem = std.heap.ArenaAllocator.init(allocator);
	defer main_mem.deinit();
	const mem = main_mem.allocator();
	var tokens = tokenize(&mem, contents);
	show_tokens(tokens);
	if (debug){
		std.debug.print("initial------------------------------\n", .{});
	}
	rl.initWindow(frame_buffer_w, frame_buffer_h, "src");
	frame_buffer_texture = rl.loadTextureFromImage(frame_buffer_image) catch {
		std.debug.print("Error creating texture\n", .{});
		return;
	};
	if (plugin){
		_ = metaprogram(&tokens, &mem, false, outfilename);
		return;
	}
	const program_len = metaprogram(&tokens, &mem, false, null);
	if (program_len) |len| {
		var outfile = std.fs.cwd().createFile(outfilename, .{.truncate=true}) catch {
			std.debug.print("Error creating file: {s}\n", .{outfilename});
			return;
		};
		defer outfile.close();
		outfile.writeAll(vm.mem[start_ip..start_ip+len]) catch {
			std.debug.print("Error writing to file: {s}\n", .{outfilename});
			return;
		};
	}
}

pub fn run_file(infilename: []u8) void {
	const allocator = std.heap.page_allocator;
	var infile = std.fs.cwd().openFile(infilename, .{}) catch {
		std.debug.print("File not found: {s}\n", .{infilename});
		return;
	};
	defer infile.close();
	const stat = infile.stat() catch {
		std.debug.print("Errored file stat: {s}\n", .{infilename});
		return;
	};
	const contents = infile.readToEndAlloc(allocator, stat.size+1) catch {
		std.debug.print("Error reading file: {s}\n", .{infilename});
		return;
	};
	defer allocator.free(contents);
	for (contents, 0..) |byte, i| {
		vm.mem[start_ip+i] = byte;
	}
	rl.initWindow(frame_buffer_w, frame_buffer_h, "src");
	frame_buffer_texture = rl.loadTextureFromImage(frame_buffer_image) catch {
		std.debug.print("Error creating texture\n", .{});
		return;
	};
	interpret(start_ip);
}

pub fn metaprogram(tokens: *Buffer(Token), mem: *const std.mem.Allocator, run: bool, headless: ?[]u8) ?u64 {
	const allocator = std.heap.page_allocator;
	var main_aux = std.heap.ArenaAllocator.init(allocator);
	var main_txt = std.heap.ArenaAllocator.init(allocator);
	defer main_aux.deinit();
	defer main_txt.deinit();
	//const txt = main_txt.allocator();
	//const aux = main_aux.allocator();
	//var text = Buffer(Token).init(txt);
	//var auxil = Buffer(Token).init(aux);
	const token_stream = import_flatten(mem, tokens) catch |err| {
		std.debug.print("Error flattening imports: {}\n", .{err});
		return null;
	};
	show_tokens(token_stream.*);
	if (debug){
		std.debug.print("flattened-------------------------------\n", .{});
	}
	var state = State{
		.binds = Buffer(Bind).init(mem.*),
		.patterns = std.StringHashMap(PatternDef).init(mem.*),
		.constructors = std.StringHashMap(Constructor).init(mem.*),
		.program = token_stream.*
	};
	state = parse(mem, &state) catch |err| {
		std.debug.print("Parse / apply error: {}\n", .{err});
		return null;
	};
	var index:u64 = 0;
	if (headless) |filename| {
		const stream = parse_plugin(mem, &state.program, &index, false) catch |err| {
			std.debug.print("Headless Plugin Parse Error: {} \n", .{err});
			return null;
		};
		var out = std.fs.cwd().createFile(filename, .{.truncate=true}) catch {
			std.debug.print("Error creating file: {s}\n", .{filename});
			return null;
		};
		defer out.close();
		for (stream.items) |t| {
			_ = out.write(t.text) catch {
				std.debug.print("Error writing to file\n", .{});
				return null;
			};
			_ = out.write(" ") catch {
				std.debug.print("Error writing to file\n", .{});
				return null;
			};
		}
		return null;
	}
	var runtime = VM.init();
	const program_len = parse_bytecode(mem, runtime.mem[start_ip..], &state.program, &index, false) catch |err| {
		std.debug.print("Bytecode Parse Error {}\n", .{err});
		return null;
	};
	vm = runtime;
	if (run){
		if (debug){
			std.debug.print("program length: {}\n", .{program_len});
			std.debug.print("parsed bytecode--------------------\n", .{});
		}
		interpret(start_ip);
	}
	return program_len;
}

pub fn import_flatten(mem: *const std.mem.Allocator, input_tokens: *Buffer(Token)) ParseError!*Buffer(Token) {
	var tokens = input_tokens;
	const allocator = std.heap.page_allocator;
	var new = mem.create(Buffer(Token)) catch {
		std.debug.print("could not allocate aux buffer for import flatten\n", .{});
		return ParseError.FileError;
	};
	new.* = Buffer(Token).init(mem.*);
	var imported = true;
	while (imported){
		var token_index: u64 = 0;
		imported = false;
		while (token_index < tokens.items.len){
			const token = tokens.items[token_index];
			if (token.tag == .USING){
				token_index += 1;
				try skip_whitespace(tokens.items, &token_index);
				const filename = tokens.items[token_index];
				token_index += 1;
				const buffer = mem.alloc(u8, 64) catch unreachable;
				const infile = std.fmt.bufPrint(buffer, "{s}{s}", .{filename.text, ".src"}) catch {
					std.debug.print("Unable to allcoate filename {s}{s}\n", .{filename.text, ".src"});
					return ParseError.FileError;
				};
				var file = std.fs.cwd().openFile(infile, .{}) catch {
					std.debug.print("File not found: {s}\n", .{infile});
					return ParseError.FileNotFound;
				};
				defer file.close();
				const stat = file.stat() catch {
					std.debug.print("Broken file stat: {s}\n", .{infile});
					return ParseError.FileNotFound;
				};
				const contents = file.readToEndAlloc(allocator, stat.size+1) catch {
					std.debug.print("Error reading file: {s}\n", .{infile});
					return ParseError.FileNotFound;
				};
				const opinion = tokenize(mem, contents);
				new.appendSlice(opinion.items)
					catch unreachable;
				imported = true;
				continue;
			}
			new.append(token)
				catch unreachable;
			token_index += 1;
		}
		if (imported){
			show_tokens(new.*);
			if (debug){
				std.debug.print("flattened once---------------------------\n", .{});
			}
			const temp = tokens;
			tokens = new;
			new = temp;
			new.clearRetainingCapacity();
		}
	}
	show_tokens(new.*);
	if (debug){
		std.debug.print("final flatten---------------------------\n", .{});
	}
	return new;
}

const ParseError = error {
	PrematureEnd,
	UnexpectedToken,
	UnexpectedEOF,
	AlternateUnmatchable,
	ConstMatched,
	BrokenComptime,
	NoHoist,
	NoArgs,
	FileNotFound,
	FileError
};

const TOKEN = enum {
	BIND, COMP_START, COMP_END,
	USING,
	IDENTIFIER,
	OPEN_BRACK, CLOSE_BRACK,
	OPEN_BRACE, CLOSE_BRACE,
	UNIQUE,
	PIPE,
	HOIST,
	PATTERN,
	WHERE,
	ANY,
	QUOTE,
	LIT,
	EQUAL,
	SEMI,
	OPEN_PAREN,
	CLOSE_PAREN,
	MOV, MOVL, MOVH,
	ADD, SUB, MUL, DIV, MOD,
	AND, OR, XOR, SHL, SHR, NOT, COM,
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
	hoist_data: ?*Buffer(Token),
	hoist_token: ?*Field
};

const ProgramText = struct {
	text: *Buffer(Token),
	binds: *Buffer(Bind)
};

pub fn tokenize(mem: *const std.mem.Allocator, text: []u8) Buffer(Token) {
	var i: u64 = 0;
	var token_map = std.StringHashMap(TOKEN).init(mem.*);
	token_map.put("bind", .BIND) catch unreachable;
	token_map.put("using_opinion", .USING) catch unreachable;
	token_map.put("hoist",.HOIST) catch unreachable;
	token_map.put("pattern",.PATTERN) catch unreachable;
	token_map.put("where",.WHERE) catch unreachable;
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
				'|' => {break :blk .PIPE;},
				'@' => {break :blk .UNIQUE;},
				'$' => {break :blk .LINE_END;},
				'#' => {break :blk .CONCAT;},
				'%' => {break :blk .WHITESPACE;},
				'!' => {break :blk .LIT;},
				'=' => {break :blk .EQUAL;},
				'(' => {break :blk .OPEN_PAREN;},
				')' => {break :blk .CLOSE_PAREN;},
				'*' => {break :blk .ANY;},
				'\'' => {break :blk .QUOTE;},
				';' => {break :blk .SEMI;},
				else => {break :blk .IDENTIFIER;}
			}
			break :blk .IDENTIFIER;
		};
		if (tag != .IDENTIFIER){
			if (escape){
				tag = .IDENTIFIER;
			}
			tokens.append(Token{.tag=tag, .text=text[i..i+1], .hoist_data=null, .hoist_token = null})
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
			break :blk text[i..i+size];
		};
		if (token_map.get(keyword)) |map_tag| {
			tag = map_tag;
			if (escape){
				tag = .IDENTIFIER;
			}
		}
		tokens.append(Token{.tag=tag, .text=keyword, .hoist_data=null, .hoist_token=null})
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
	token_map.put("mod", .MOD) catch unreachable;
	token_map.put("and", .AND) catch unreachable;
	token_map.put("xor", .XOR) catch unreachable;
	token_map.put("or", .OR) catch unreachable;
	token_map.put("shl", .SHL) catch unreachable;
	token_map.put("shr", .SHR) catch unreachable;
	token_map.put("not", .NOT) catch unreachable;
	token_map.put("com", .COM) catch unreachable;
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
		std.debug.print("{s} ", .{token.text});
	}
	std.debug.print("\n", .{});
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

const PatternError = error {
	MissingKeyword,
	ExhaustedAlternate,
	ExclusionPresent,
	UnexpectedEOF
};

pub fn token_equal(a: *Token, b: *Token) bool {
	return std.mem.eql(u8, a.text, b.text);
}

pub fn to_byte_token_slice(mem: *const std.mem.Allocator, c: u8) []u8 {
	const buf: []u8 = mem.alloc(u8, 2) catch unreachable;
	const text = std.fmt.bufPrint(buf, "{x:02}", .{c}) catch unreachable;
	return text;
}

pub fn mk_token_from_u64(mem: *const std.mem.Allocator, val: u64) Token {
	const buf = mem.alloc(u8, 20) catch unreachable;
	const slice = std.fmt.bufPrint(buf, "{}", .{val}) catch unreachable;
	return Token{.tag=.IDENTIFIER, .text=slice, .hoist_data=null, .hoist_token = null};
}

pub fn new_uid(mem: *const std.mem.Allocator) []u8 {
	var new = mem.alloc(u8, uid.len) catch unreachable;
	var i:u64 = 0;
	var inc:bool = false;
	while (i < new.len) {
		if (uid[i] < 'Z'){
			new[i] = uid[i]+1;
			i += 1;
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
	uid = new;
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

pub fn parse_plugin(mem: *const std.mem.Allocator, tokens: *const Buffer(Token), token_index: *u64, comp: bool) ParseError!Buffer(Token) {
	try retokenize(mem, tokens);
	var output = Buffer(Token).init(mem.*);
	while (token_index.* < tokens.items.len){
		skip_whitespace(tokens.items, token_index) catch {
			return output;
		};
		if (token_index.* > tokens.items.len){
			std.debug.print("Expected opcode, found end of file\n", .{});
			return ParseError.UnexpectedEOF;
		}
		const token = tokens.items[token_index.*];
		token_index.* += 1;
		switch (token.tag){
			.COMP_START => {
				const comp_stack = comp_section;
				comp_section = true;
				if (debug){
					std.debug.print("Entering comp segment\n", .{});
				}
				_ = try parse_bytecode(mem, vm.mem[frame_buffer..vm.mem.len], tokens, token_index, true);
				if (debug){
					std.debug.print("Parsed comp segment\n", .{});
				}
				interpret(start_ip);
				if (debug){
					std.debug.print("Exiting comp segment\n", .{});
				}
				comp_section = comp_stack;
				continue;
			},
			.COMP_END => {
				if (comp == false){
					continue;
				}
				return output;
			},
			.BIND => {
				skip_whitespace(tokens.items, token_index) catch {
					return output;
				};
				const name = tokens.items[token_index.*];
				token_index.* += 1;
				if (name.tag != .IDENTIFIER){
					std.debug.print("Expected name for transfer bind, found {s}\n", .{name.text});
					return ParseError.UnexpectedToken;
				}
				skip_whitespace(tokens.items, token_index) catch {
					return output;
				};
				if (tokens.items[token_index.*].tag != .EQUAL){
					std.debug.print("Expected = for transfer bind, found {s}\n", .{tokens.items[token_index.*].text});
					return ParseError.UnexpectedToken;
				}
				token_index.* += 1;
				skip_whitespace(tokens.items, token_index) catch {
					return output;
				};
				const comp_stack = comp_section;
				comp_section = true;
				const loc = try parse_location(mem, tokens, token_index);
				comp_section = comp_stack;
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
			else => {
				const val = persistent.get(token.text);
				if (val) |v| {
					const tok_val = mk_token_from_u64(mem, v);
					output.append(tok_val)
						catch unreachable;
					continue;
				}
				output.append(token)
					catch unreachable;
			}
		}
	}
	return output;
}

pub fn parse_bytecode(mem: *const std.mem.Allocator, data: []u8, tokens: *const Buffer(Token), token_index: *u64, comp: bool) ParseError!u64 {
	try retokenize(mem, tokens);
	var labels = std.StringHashMap(u64).init(mem.*);
	const index_save = token_index.*;
	var i: u64 = 0;
	outer: for (0..2) |pass| {
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
					const comp_stack = comp_section;
					comp_section = true;
					if (debug) {
						std.debug.print("Entering comp segment\n", .{});
					}
					_ = try parse_bytecode(mem, vm.mem[frame_buffer..vm.mem.len], tokens, token_index, true);
					if (debug) {
						std.debug.print("Parsed comp segment\n", .{});
					}
					if (pass == 0){
						interpret(start_ip);
						if (debug) {
							std.debug.print("Exiting comp segment\n", .{});
						}
					}
					comp_section = comp_stack;
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
						continue :outer;
					};
					const name = tokens.items[token_index.*];
					token_index.* += 1;
					if (name.tag != .IDENTIFIER){
						std.debug.print("Expected name for transfer bind, found {s}\n", .{name.text});
						return ParseError.UnexpectedToken;
					}
					skip_whitespace(tokens.items, token_index) catch {
						continue :outer;
					};
					if (tokens.items[token_index.*].tag != .EQUAL){
						std.debug.print("Expected = for transfer bind, found {s}\n", .{tokens.items[token_index.*].text});
						return ParseError.UnexpectedToken;
					}
					token_index.* += 1;
					skip_whitespace(tokens.items, token_index) catch {
						continue :outer;
					};
					const is_ip = tokens.items[token_index.*];
					if (is_ip.tag == .IP){
						token_index.* += 1;
						if (pass == 0){
							labels.put(name.text, (i/8)+(start_ip/8))
								catch unreachable;
						}
						continue;
					}
					const comp_stack = comp_section;
					comp_section = true;
					const loc = try parse_location(mem, tokens, token_index);
					comp_section = comp_stack;
					const val = val64(loc) catch |err| {
						std.debug.print("Encountered error in Persistence binding: {}\n", .{err});
						return ParseError.UnexpectedToken;
					};
					if (pass == 0){
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
				.MOVH => {
					op = Instruction {
						.tag=.movh_ii,
						.data=.{
							.move=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.src=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.MOVL => {
					op = Instruction {
						.tag=.movl_ii,
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
				.MOD => {
					op = Instruction{
						.tag=.mod_iii,
						.data=.{
							.alu=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.AND => {
					op = Instruction{
						.tag=.and_iii,
						.data=.{
							.alu=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.XOR => {
					op = Instruction{
						.tag=.xor_iii,
						.data=.{
							.alu=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.OR => {
					op = Instruction{
						.tag=.or_iii,
						.data=.{
							.alu=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.SHL => {
					op = Instruction{
						.tag=.shl_iii,
						.data=.{
							.alu=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.SHR => {
					op = Instruction{
						.tag=.shr_iii,
						.data=.{
							.alu=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=try parse_location_or_label(mem, tokens, token_index, labels, false)
							}
						}
					};
				},
				.NOT => {
					op = Instruction{
						.tag=.not_ii,
						.data=.{
							.alu=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=Location{.literal=0}
							}
						}
					};
				},
				.COM => {
					op = Instruction{
						.tag=.com_ii,
						.data=.{
							.alu=.{
								.dest=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.left=try parse_location_or_label(mem, tokens, token_index, labels, false),
								.right=Location{.literal=0}
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
			while (token.tag == .SPACE or token.tag == .TAB or token.tag == .NEW_LINE){
				token = tokens.items[token_index.*];
				token_index.* += 1;
			}
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
			while (token.tag == .SPACE or token.tag == .TAB or token.tag == .NEW_LINE){
				token = tokens.items[token_index.*];
				token_index.* += 1;
			}
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
	const value = std.fmt.parseInt(u64, token.text, 16) catch {
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

pub fn loc64(l: Location, val: u64) void {
	switch (l){
		.immediate => {
			store_u64(l.immediate, val);
		},
		.literal => {
			return;
		}, 
		.register => {
			switch (l.register){
				.R0 => {store_u64(vm.r0, val);},
				.R1 => {store_u64(vm.r1, val);},
				.R2 => {store_u64(vm.r2, val);},
				.R3 => {store_u64(vm.r3, val);},
				.IP => {store_u64(vm.ip, val);},
				else => {
					return;
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
	mov_di, mov_dl, mov_dd,
	movh_ii, movh_il, movh_id,
	movh_di, movh_dl, movh_dd,
	movl_ii, movl_il, movl_id,
	movl_di, movl_dl, movl_dd,

	add_iii, add_iil, add_iid, add_ili, add_ill, add_ild, add_idi, add_idl, add_idd,
	add_dii, add_dil, add_did, add_dli, add_dll, add_dld, add_ddi, add_ddl, add_ddd,
	sub_iii, sub_iil, sub_iid, sub_ili, sub_ill, sub_ild, sub_idi, sub_idl, sub_idd,
	sub_dii, sub_dil, sub_did, sub_dli, sub_dll, sub_dld, sub_ddi, sub_ddl, sub_ddd,
	mul_iii, mul_iil, mul_iid, mul_ili, mul_ill, mul_ild, mul_idi, mul_idl, mul_idd,
	mul_dii, mul_dil, mul_did, mul_dli, mul_dll, mul_dld, mul_ddi, mul_ddl, mul_ddd,
	div_iii, div_iil, div_iid, div_ili, div_ill, div_ild, div_idi, div_idl, div_idd,
	div_dii, div_dil, div_did, div_dli, div_dll, div_dld, div_ddi, div_ddl, div_ddd,
	mod_iii, mod_iil, mod_iid, mod_ili, mod_ill, mod_ild, mod_idi, mod_idl, mod_idd,
	mod_dii, mod_dil, mod_did, mod_dli, mod_dll, mod_dld, mod_ddi, mod_ddl, mod_ddd,
	and_iii, and_iil, and_iid, and_ili, and_ill, and_ild, and_idi, and_idl, and_idd,
	and_dii, and_dil, and_did, and_dli, and_dll, and_dld, and_ddi, and_ddl, and_ddd,
	xor_iii, xor_iil, xor_iid, xor_ili, xor_ill, xor_ild, xor_idi, xor_idl, xor_idd,
	xor_dii, xor_dil, xor_did, xor_dli, xor_dll, xor_dld, xor_ddi, xor_ddl, xor_ddd,
	or_iii, or_iil, or_iid, or_ili, or_ill, or_ild, or_idi, or_idl, or_idd,
	or_dii, or_dil, or_did, or_dli, or_dll, or_dld, or_ddi, or_ddl, or_ddd,
	shl_iii, shl_iil, shl_iid, shl_ili, shl_ill, shl_ild, shl_idi, shl_idl, shl_idd,
	shl_dii, shl_dil, shl_did, shl_dli, shl_dll, shl_dld, shl_ddi, shl_ddl, shl_ddd,
	shr_iii, shr_iil, shr_iid, shr_ili, shr_ill, shr_ild, shr_idi, shr_idl, shr_idd,
	shr_dii, shr_dil, shr_did, shr_dli, shr_dll, shr_dld, shr_ddi, shr_ddl, shr_ddd,

	not_ii, not_il,
	com_ii, com_il,

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

const OpBytesFn = *const fn (*align(1) u64) bool;

pub fn interpret(start:u64) void {
	vm.words = std.mem.bytesAsSlice(u64, vm.mem[0..]);
	vm.half_words = std.mem.bytesAsSlice(u32, vm.mem[0..]);
	const ip = &vm.words[vm.ip/8];
	ip.* = start/8;
	const ops: [233]OpBytesFn = .{
		mov_ii_bytes, mov_il_bytes, mov_id_bytes, mov_di_bytes, mov_dl_bytes, mov_dd_bytes,
		movh_ii_bytes, movh_il_bytes, movh_id_bytes, movh_di_bytes, movh_dl_bytes, movh_dd_bytes,
		movl_ii_bytes, movl_il_bytes, movl_id_bytes, movl_di_bytes, movl_dl_bytes, movl_dd_bytes,
		add_iii_bytes, add_iil_bytes, add_iid_bytes, add_ili_bytes, add_ill_bytes, add_ild_bytes, add_idi_bytes, add_idl_bytes, add_idd_bytes, add_dii_bytes, add_dil_bytes, add_did_bytes, add_dli_bytes, add_dll_bytes, add_dld_bytes, add_ddi_bytes, add_ddl_bytes, add_ddd_bytes,
		sub_iii_bytes, sub_iil_bytes, sub_iid_bytes, sub_ili_bytes, sub_ill_bytes, sub_ild_bytes, sub_idi_bytes, sub_idl_bytes, sub_idd_bytes, sub_dii_bytes, sub_dil_bytes, sub_did_bytes, sub_dli_bytes, sub_dll_bytes, sub_dld_bytes, sub_ddi_bytes, sub_ddl_bytes, sub_ddd_bytes,
		mul_iii_bytes, mul_iil_bytes, mul_iid_bytes, mul_ili_bytes, mul_ill_bytes, mul_ild_bytes, mul_idi_bytes, mul_idl_bytes, mul_idd_bytes, mul_dii_bytes, mul_dil_bytes, mul_did_bytes, mul_dli_bytes, mul_dll_bytes, mul_dld_bytes, mul_ddi_bytes, mul_ddl_bytes, mul_ddd_bytes,
		div_iii_bytes, div_iil_bytes, div_iid_bytes, div_ili_bytes, div_ill_bytes, div_ild_bytes, div_idi_bytes, div_idl_bytes, div_idd_bytes, div_dii_bytes, div_dil_bytes, div_did_bytes, div_dli_bytes, div_dll_bytes, div_dld_bytes, div_ddi_bytes, div_ddl_bytes, div_ddd_bytes,
		mod_iii_bytes, mod_iil_bytes, mod_iid_bytes, mod_ili_bytes, mod_ill_bytes, mod_ild_bytes, mod_idi_bytes, mod_idl_bytes, mod_idd_bytes, mod_dii_bytes, mod_dil_bytes, mod_did_bytes, mod_dli_bytes, mod_dll_bytes, mod_dld_bytes, mod_ddi_bytes, mod_ddl_bytes, mod_ddd_bytes,
		and_iii_bytes, and_iil_bytes, and_iid_bytes, and_ili_bytes, and_ill_bytes, and_ild_bytes, and_idi_bytes, and_idl_bytes, and_idd_bytes, and_dii_bytes, and_dil_bytes, and_did_bytes, and_dli_bytes, and_dll_bytes, and_dld_bytes, and_ddi_bytes, and_ddl_bytes, and_ddd_bytes,
		xor_iii_bytes, xor_iil_bytes, xor_iid_bytes, xor_ili_bytes, xor_ill_bytes, xor_ild_bytes, xor_idi_bytes, xor_idl_bytes, xor_idd_bytes, xor_dii_bytes, xor_dil_bytes, xor_did_bytes, xor_dli_bytes, xor_dll_bytes, xor_dld_bytes, xor_ddi_bytes, xor_ddl_bytes, xor_ddd_bytes,
		or_iii_bytes, or_iil_bytes, or_iid_bytes, or_ili_bytes, or_ill_bytes, or_ild_bytes, or_idi_bytes, or_idl_bytes, or_idd_bytes, or_dii_bytes, or_dil_bytes, or_did_bytes, or_dli_bytes, or_dll_bytes, or_dld_bytes, or_ddi_bytes, or_ddl_bytes, or_ddd_bytes,
		shl_iii_bytes, shl_iil_bytes, shl_iid_bytes, shl_ili_bytes, shl_ill_bytes, shl_ild_bytes, shl_idi_bytes, shl_idl_bytes, shl_idd_bytes, shl_dii_bytes, shl_dil_bytes, shl_did_bytes, shl_dli_bytes, shl_dll_bytes, shl_dld_bytes, shl_ddi_bytes, shl_ddl_bytes, shl_ddd_bytes,
		shr_iii_bytes, shr_iil_bytes, shr_iid_bytes, shr_ili_bytes, shr_ill_bytes, shr_ild_bytes, shr_idi_bytes, shr_idl_bytes, shr_idd_bytes, shr_dii_bytes, shr_dil_bytes, shr_did_bytes, shr_dli_bytes, shr_dll_bytes, shr_dld_bytes, shr_ddi_bytes, shr_ddl_bytes, shr_ddd_bytes,
		not_ii_bytes, not_il_bytes, com_ii_bytes, com_il_bytes,
		cmp_ii_bytes, cmp_il_bytes, cmp_id_bytes, cmp_li_bytes, cmp_ll_bytes, cmp_ld_bytes, cmp_di_bytes, cmp_dl_bytes, cmp_dd_bytes,
		jmp_i_bytes, jmp_l_bytes, jmp_d_bytes, jne_i_bytes, jne_l_bytes, jne_d_bytes, jeq_i_bytes, jeq_l_bytes, jeq_d_bytes, jle_i_bytes, jle_l_bytes, jle_d_bytes, jlt_i_bytes, jlt_l_bytes, jlt_d_bytes, jge_i_bytes, jge_l_bytes, jge_d_bytes, jgt_i_bytes, jgt_l_bytes, jgt_d_bytes,
		int_bytes
	};
	var running = true;
	while (running) {
		if (debug){
			if (!comp_section){
				const stdout = std.io.getStdOut().writer();
				stdout.print("\x1b[2J\x1b[H", .{}) catch unreachable;
				debug_show_instruction_ref_path(vm.words[vm.ip/8]);
				debug_show_instruction_ref_path(vm.words[vm.ip/8]-2);
				stdout.print("\x1b[H", .{}) catch unreachable;
				debug_show_registers();
				debug_show_instructions();
				var stdin = std.io.getStdIn().reader();
				var buffer: [1]u8 = undefined;
				_ = stdin.read(&buffer) catch unreachable;
			}
		}
		running = ops[vm.words[ip.*]&0xFFFFFFFF](ip);
	}
}

pub fn debug_show_registers() void {
	const stdout = std.io.getStdOut().writer();
	stdout.print(",---------------------.\n", .{}) catch unreachable;
	stdout.print("| r0: {x:016} |\n", .{vm.words[vm.r0/8]}) catch unreachable;
	stdout.print("| r1: {x:016} |\n", .{vm.words[vm.r1/8]}) catch unreachable;
	stdout.print("| r2: {x:016} |\n", .{vm.words[vm.r2/8]}) catch unreachable;
	stdout.print("| r3: {x:016} |\n", .{vm.words[vm.r3/8]}) catch unreachable;
	stdout.print("| \x1b[1;31mip: {x:016}\x1b[0m |\n", .{vm.words[vm.ip/8]*8}) catch unreachable;
	stdout.print("`----------------------'\n\n\n\n", .{}) catch unreachable;
}

pub fn debug_show_instructions() void {
	const stdout = std.io.getStdOut().writer();
	stdout.print(",-----------------------------------------------------.\n", .{}) catch unreachable;
	var inst_start = vm.words[vm.ip/8];
	if (inst_start < 16){
		inst_start = 0;
	}
	else {
		inst_start -= 16;
	}
	const inst_end = inst_start+32;
	while (inst_start < inst_end): (inst_start += 2){
		stdout.print("| ", .{}) catch unreachable;
		if (inst_start == vm.words[vm.ip/8]){
			stdout.print("\x1b[1;31m", .{}) catch unreachable;
		}
		stdout.print("{x:016}: {x:016} {x:016}", .{inst_start*8, vm.words[inst_start], vm.words[inst_start+1]}) catch unreachable;
		if (inst_start == vm.words[vm.ip/8]){
			stdout.print("\x1b[0m", .{}) catch unreachable;
		}
		stdout.print(" |\n",.{}) catch unreachable;
	}
	stdout.print("`-----------------------------------------------------'\n", .{}) catch unreachable;
}

pub fn debug_show_instruction_ref_path(ip: u64) void {
	const stdout = std.io.getStdOut().writer();
	const inst_a = vm.words[ip];
	const inst_b = vm.words[ip+1];
	const a = inst_a >> 32;
	const b = (inst_b & 0xFFFFFFFF);
	const c = inst_b >> 32;
	stdout.print("                           ,--------------------------------------------------.\n", .{}) catch unreachable;
	debug_show_ref_path(a);
	debug_show_ref_path(b);
	debug_show_ref_path(c);
	stdout.print("                           `--------------------------------------------------'\n", .{}) catch unreachable;
}

pub fn debug_show_ref_path(lit: u64) void {
	const stdout = std.io.getStdOut().writer();
	var ref:u64 = 0;
	var deref:u64 = 0;
	if (lit/8 < vm.words.len){
		ref = vm.words[lit/8];
	}
	if (ref < vm.words.len){
		deref = vm.words[ref/8];
	}
	stdout.print("                           | {x:08} -> {x:016} -> {x:016} |\n", .{lit, ref, deref}) catch unreachable;
}

pub fn mov_ii_bytes(ip: *align(1) u64) bool{
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest = (args & 0xFFFFFFFF);
	const src_name = args >> 32;
	const src = vm.words[src_name >> 3];
	vm.words[dest >> 3] = src;
	return true;
}

pub fn mov_il_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest = (args & 0xFFFFFFFF);
	const src = args >> 32;
	vm.words[dest >> 3] = src;
	return true;
}

pub fn mov_id_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest = (args & 0xFFFFFFFF);
	const src_name = args >> 32;
	const src_imm = vm.words[src_name >> 3];
	const src = vm.words[src_imm >> 3];
	vm.words[dest >> 3] = src;
	return true;
}

pub fn mov_di_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest_name = (args & 0xFFFFFFFF);
	const dest = vm.words[dest_name >> 3];
	const src_name = args >> 32;
	const src = vm.words[src_name >> 3];
	vm.words[dest >> 3]  = src;
	return true;
}

pub fn mov_dl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest_name = (args & 0xFFFFFFFF);
	const dest = vm.words[dest_name >> 3];
	const src = args >> 32;
	vm.words[dest >> 3] = src;
	return true;
}

pub fn mov_dd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest_name = (args & 0xFFFFFFFF);
	const dest = vm.words[dest_name >> 3];
	const src_name = args >> 32;
	const src_imm = vm.words[src_name >> 3];
	const src = vm.words[src_imm >> 3];
	vm.words[dest >> 3] = src;
	return true;
}

pub fn movl_ii_bytes(ip: *align(1) u64) bool{
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest = (args & 0xFFFFFFFF);
	const src_name = args >> 32;
	const src = vm.words[src_name >> 3];
	vm.words[dest >> 3] = (vm.words[dest >> 3] & 0xFFFFFFFF00000000) | (src & 0xFFFFFFFF);
	return true;
}

pub fn movl_il_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest = (args & 0xFFFFFFFF);
	const src = args >> 32;
	vm.words[dest >> 3] = (vm.words[dest >> 3] & 0xFFFFFFFF00000000) | (src & 0xFFFFFFFF);
	return true;
}

pub fn movl_id_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest = (args & 0xFFFFFFFF);
	const src_name = args >> 32;
	const src_imm = vm.words[src_name >> 3];
	const src = vm.words[src_imm >> 3];
	vm.words[dest >> 3] = (vm.words[dest >> 3] & 0xFFFFFFFF00000000) | (src & 0xFFFFFFFF);
	return true;
}

pub fn movl_di_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest_name = (args & 0xFFFFFFFF);
	const dest = vm.words[dest_name >> 3];
	const src_name = args >> 32;
	const src = vm.words[src_name >> 3];
	vm.words[dest >> 3] = (vm.words[dest >> 3] & 0xFFFFFFFF00000000) | (src & 0xFFFFFFFF);
	return true;
}

pub fn movl_dl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest_name = (args & 0xFFFFFFFF);
	const dest = vm.words[dest_name >> 3];
	const src = args >> 32;
	vm.words[dest >> 3] = (vm.words[dest >> 3] & 0xFFFFFFFF00000000) | (src & 0xFFFFFFFF);
	return true;
}

pub fn movl_dd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest_name = (args & 0xFFFFFFFF);
	const dest = vm.words[dest_name >> 3];
	const src_name = args >> 32;
	const src_imm = vm.words[src_name >> 3];
	const src = vm.words[src_imm >> 3];
	vm.words[dest >> 3] = (vm.words[dest >> 3] & 0xFFFFFFFF00000000) | (src & 0xFFFFFFFF);
	return true;
}

pub fn movh_ii_bytes(ip: *align(1) u64) bool{
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest = (args & 0xFFFFFFFF);
	const src_name = args >> 32;
	const src = vm.words[src_name >> 3];
	vm.words[dest >> 3] = (vm.words[dest >> 3] & 0xFFFFFFFF) | (src << 32);
	return true;
}

pub fn movh_il_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest = (args & 0xFFFFFFFF);
	const src = args >> 32;
	vm.words[dest >> 3] = (vm.words[dest >> 3] & 0xFFFFFFFF) | (src << 32);
	return true;
}

pub fn movh_id_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest = (args & 0xFFFFFFFF);
	const src_name = args >> 32;
	const src_imm = vm.words[src_name >> 3];
	const src = vm.words[src_imm >> 3];
	vm.words[dest >> 3] = (vm.words[dest >> 3] & 0xFFFFFFFF) | (src << 32);
	return true;
}

pub fn movh_di_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest_name = (args & 0xFFFFFFFF);
	const dest = vm.words[dest_name >> 3];
	const src_name = args >> 32;
	const src = vm.words[src_name >> 3];
	vm.words[dest >> 3] = (vm.words[dest >> 3] & 0xFFFFFFFF) | (src << 32);
	return true;
}

pub fn movh_dl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest_name = (args & 0xFFFFFFFF);
	const dest = vm.words[dest_name >> 3];
	const src = args >> 32;
	vm.words[dest >> 3] = (vm.words[dest >> 3] & 0xFFFFFFFF) | (src << 32);
	return true;
}

pub fn movh_dd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const args = vm.words[p+1];
	const dest_name = (args & 0xFFFFFFFF);
	const dest = vm.words[dest_name >> 3];
	const src_name = args >> 32;
	const src_imm = vm.words[src_name >> 3];
	const src = vm.words[src_imm >> 3];
	vm.words[dest >> 3] = (vm.words[dest >> 3] & 0xFFFFFFFF) | (src << 32);
	return true;
}

pub fn add_iii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_iil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_iid_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_ili_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_ill_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_ild_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_idi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_idl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_idd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_dii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_dil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_did_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_dli_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_dll_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_dld_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_ddi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_ddl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn add_ddd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a + b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_iii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_iil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_iid_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_ili_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_ill_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_ild_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_idi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_idl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_idd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_dii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_dil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_did_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_dli_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_dll_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_dld_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_ddi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_ddl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn sub_ddd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a - b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_iii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_iil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_iid_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_ili_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_ill_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_ild_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_idi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_idl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_idd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_dii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_dil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_did_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_dli_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_dll_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_dld_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_ddi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_ddl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mul_ddd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a * b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_iii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_iil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_iid_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_ili_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_ill_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_ild_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_idi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_idl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_idd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_dii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_dil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_did_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_dli_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_dll_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_dld_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_ddi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_ddl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn div_ddd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a / b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_iii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_iil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_iid_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_ili_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_ill_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_ild_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_idi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_idl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_idd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_dii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_dil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_did_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_dli_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_dll_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_dld_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_ddi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_ddl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn mod_ddd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a % b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_iii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_iil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_iid_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_ili_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_ill_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_ild_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_idi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_idl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_idd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_dii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_dil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_did_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_dli_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_dll_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_dld_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_ddi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_ddl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn and_ddd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a & b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_iii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_iil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_iid_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_ili_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_ill_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_ild_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_idi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_idl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_idd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_dii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_dil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_did_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_dli_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_dll_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_dld_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_ddi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_ddl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn or_ddd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a | b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_iii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_iil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_iid_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_ili_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_ill_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_ild_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_idi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_idl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_idd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_dii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_dil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_did_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_dli_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_dll_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_dld_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_ddi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_ddl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn xor_ddd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a ^ b;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_iii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_iil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_iid_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_ili_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_ill_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_ild_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_idi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_idl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_idd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_dii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_dil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_did_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_dli_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_dll_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_dld_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_ddi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_ddl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shl_ddd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a << @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_iii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_iil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_iid_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_ili_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_ill_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_ild_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_idi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_idl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_idd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_dii_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b = vm.words[b_name >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_dil_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a = vm.words[a_name >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_did_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_dli_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b = vm.words[b_name >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_dll_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_dld_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const b_imm = vm.words[b_name >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_ddi_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_name >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_ddl_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const a = vm.words[a_imm >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn shr_ddd_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest_arg = dest_chunk >> 32;
	const args = vm.words[p+1];
	const dest = vm.words[dest_arg >> 3];
	const a_name = (args & 0xFFFFFFFF);
	const b_name = args >> 32;
	const a_imm = vm.words[a_name >> 3];
	const b_imm = vm.words[b_name >> 3];
	const a = vm.words[a_imm >> 3];
	const b = vm.words[b_imm >> 3];
	const c = a >> @truncate(b);
	vm.words[dest >> 3] = c;
	return true;
}

pub fn not_ii_bytes(ip: *align(1) u64) bool{
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const a = vm.words[a_name >> 3];
	var c: u64 = 1;
	if (a != 0) {
		c = 0;
	}
	vm.words[dest >> 3] = c;
	return true;
}

pub fn not_il_bytes(ip: *align(1) u64) bool{
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	var c: u64 = 1;
	if (a != 0) {
		c = 0;
	}
	vm.words[dest >> 3] = c;
	return true;
}

pub fn com_ii_bytes(ip: *align(1) u64) bool{
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a_name = (args & 0xFFFFFFFF);
	const a = vm.words[a_name >> 3];
	const c = ~a;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn com_il_bytes(ip: *align(1) u64) bool{
	const p = ip.*;
	ip.* += 2;
	const dest_chunk = vm.words[p];
	const dest = dest_chunk >> 32;
	const args = vm.words[p+1];
	const a = (args & 0xFFFFFFFF);
	const c = ~a;
	vm.words[dest >> 3] = c;
	return true;
}

pub fn cmp_ii_bytes(ip: *align(1) u64) bool {
	const args = vm.words[ip.*+1];
	const left_name = (args & 0xFFFFFFFF);
	const right_name = args >> 32;
	const left = vm.words[left_name >> 3];
	const right = vm.words[right_name >> 3];
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 2;
	return true;
}

pub fn cmp_il_bytes(ip: *align(1) u64) bool {
	const args = vm.words[ip.*+1];
	const left_name = (args & 0xFFFFFFFF);
	const right_name = args >> 32;
	const left = vm.words[left_name >> 3];
	const right = vm.words[right_name >> 3];
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 2;
	return true;
}

pub fn cmp_id_bytes(ip: *align(1) u64) bool {
	const args = vm.words[ip.*+1];
	const left_name = (args & 0xFFFFFFFF);
	const left = vm.words[left_name >> 3];
	const right_name = args >> 32;
	const right_imm = vm.words[right_name >> 3];
	const right = vm.words[right_imm >> 3];
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 2;
	return true;
}

pub fn cmp_li_bytes(ip: *align(1) u64) bool {
	const args = vm.words[ip.*+1];
	const left = (args & 0xFFFFFFFF);
	const right_name = args >> 32;
	const right = vm.words[right_name >> 3];
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 2;
	return true;
}

pub fn cmp_ll_bytes(ip: *align(1) u64) bool {
	const args = vm.words[ip.*+1];
	const left = (args & 0xFFFFFFFF);
	const right = args >> 32;
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 2;
	return true;
}

pub fn cmp_ld_bytes(ip: *align(1) u64) bool {
	const args = vm.words[ip.*+1];
	const left = (args & 0xFFFFFFFF);
	const right_name = args >> 32;
	const right_imm = vm.words[right_name >> 3];
	const right = vm.words[right_imm >> 3];
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 2;
	return true;
}

pub fn cmp_di_bytes(ip: *align(1) u64) bool {
	const args = vm.words[ip.*+1];
	const left_name = (args & 0xFFFFFFFF);
	const left_imm = vm.words[left_name >> 3];
	const left = vm.words[left_imm >> 3];
	const right_name = args >> 32;
	const right = vm.words[right_name >> 3];
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 2;
	return true;
}

pub fn cmp_dl_bytes(ip: *align(1) u64) bool {
	const args = vm.words[ip.*+1];
	const left_name = (args & 0xFFFFFFFF);
	const left_imm = vm.words[left_name >> 3];
	const left = vm.words[left_imm >> 3];
	const right = args >> 32;
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 2;
	return true;
}

pub fn cmp_dd_bytes(ip: *align(1) u64) bool {
	const args = vm.words[ip.*+1];
	const left_name = (args & 0xFFFFFFFF);
	const left_imm = vm.words[left_name >> 3];
	const left = vm.words[left_imm >> 3];
	const right_name = args >> 32;
	const right_imm = vm.words[right_name >> 3];
	const right = vm.words[right_imm >> 3];
	if (left > right){
		vm.mem[vm.sr] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr] = 2;
	}
	else {
		vm.mem[vm.sr] = 0;
	}
	ip.* += 2;
	return true;
}

pub fn jmp_i_bytes(ip: *align(1) u64) bool {
	const label = vm.words[ip.*+1] >> 32;
	const dest = vm.words[label >> 3];
	ip.* = dest;
	return true;
}

pub fn jmp_l_bytes(ip: *align(1) u64) bool {
	const label = vm.words[ip.*+1] >> 32;
	ip.* = label;
	return true;
}

pub fn jmp_d_bytes(ip: *align(1) u64) bool {
	const label = vm.words[ip.*+1] >> 32;
	const label_imm = vm.words[label >> 3];
	const dest = vm.words[label_imm >> 3];
	ip.* = dest;
	return true;
}

pub fn jne_i_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] != 0){
		const label = vm.words[ip.*+1] >> 32;
		const dest = vm.words[label >> 3];
		ip.* = dest;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jne_l_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] != 0){
		const label = vm.words[ip.*+1] >> 32;
		ip.* = label;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jne_d_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] != 0){
		const label = vm.words[ip.*+1] >> 32;
		const dest_imm = vm.words[label >> 3];
		const dest = vm.words[dest_imm >> 3];
		ip.* = dest;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jeq_i_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] == 0){
		const label = vm.words[ip.*+1] >> 32;
		const dest = vm.words[label >> 3];
		ip.* = dest;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jeq_l_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] == 0){
		const label = vm.words[ip.*+1] >> 32;
		ip.* = label;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jeq_d_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] == 0){
		const label = vm.words[ip.*+1] >> 32;
		const dest_imm = vm.words[label >> 3];
		const dest = vm.words[dest_imm >> 3];
		ip.* = dest;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jgt_i_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] == 1){
		const label = vm.words[ip.*+1] >> 32;
		const dest = vm.words[label >> 3];
		ip.* = dest;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jgt_l_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] == 1){
		const label = vm.words[ip.*+1] >> 32;
		ip.* = label;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jgt_d_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] == 1){
		const label = vm.words[ip.*+1] >> 32;
		const dest_imm = vm.words[label >> 3];
		const dest = vm.words[dest_imm >> 3];
		ip.* = dest;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jge_i_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] != 2){
		const label = vm.words[ip.*+1] >> 32;
		const dest = vm.words[label >> 3];
		ip.* = dest;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jge_l_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] != 2){
		const label = vm.words[ip.*+1] >> 32;
		ip.* = label;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jge_d_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] != 2){
		const label = vm.words[ip.*+1] >> 32;
		const dest_imm = vm.words[label >> 3];
		const dest = vm.words[dest_imm >> 3];
		ip.* = dest;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jlt_i_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] == 2){
		const label = vm.words[ip.*+1] >> 32;
		const dest = vm.words[label >> 3];
		ip.* = dest;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jlt_l_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] == 2){
		const label = vm.words[ip.*+1] >> 32;
		ip.* = label;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jlt_d_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] == 2){
		const label = vm.words[ip.*+1] >> 32;
		const dest_imm = vm.words[label >> 3];
		const dest = vm.words[dest_imm >> 3];
		ip.* = dest;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jle_i_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] != 1){
		const label = vm.words[ip.*+1] >> 32;
		const dest = vm.words[label >> 3];
		ip.* = dest;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jle_l_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] != 1){
		const label = vm.words[ip.*+1] >> 32;
		ip.* = label;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jle_d_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr] != 1){
		const label = vm.words[ip.*+1] >> 32;
		const dest_imm = vm.words[label >> 3];
		const dest = vm.words[dest_imm >> 3];
		ip.* = dest;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn int_bytes(ip: *align(1) u64) bool {
	ip.* += 2;
	switch (vm.mem[vm.r0]){
		0 => {
			rl.updateTexture(frame_buffer_texture, &vm.mem[0]);
			rl.beginDrawing();
			rl.drawTexture(frame_buffer_texture, 0, 0, .white);
			rl.endDrawing();
			const fps = rl.getFPS();
			std.debug.print("{}\n", .{fps});
			return true;
		},
		1 => {
			return false;
		},
		2 => {
			std.debug.print("{c}", .{vm.mem[vm.r1]});
			return true;
		},
		3 => {
			if (rl.isKeyDown(@enumFromInt(vm.words[vm.r1/8]))){
				vm.mem[vm.r2] = 1;
				return true;
			}
			vm.mem[vm.r2] = 0;
			return true;
		},
		4 => {
			if (rl.isKeyPressed(@enumFromInt(vm.words[vm.r1/8]))){
				vm.mem[vm.r2] = 1;
				return true;
			}
			vm.mem[vm.r2] = 0;
			return true;
		},
		5 => {
			const mp = rl.getMousePosition();
			vm.mem[vm.r1] = @intFromFloat(mp.x);
			vm.mem[vm.r2] = @intFromFloat(mp.y);
			return true;
		},
		6 => {
			if (rl.isMouseButtonDown(@enumFromInt(vm.words[vm.r1/8]))){
				vm.mem[vm.r2] = 1;
				return true;
			}
			vm.mem[vm.r2] = 0;
			return true;
		},
		7 => {
			if (rl.isMouseButtonPressed(@enumFromInt(vm.words[vm.r1/8]))){
				vm.mem[vm.r2] = 1;
				return true;
			}
			vm.mem[vm.r2] = 0;
			return true;
		},
		8 => {
			const addr = vm.mem[vm.r1];
			const len = vm.mem[vm.r2];
			const dest = vm.mem[vm.r3];
			const slice = vm.mem[addr..addr+len];
			compile_and_load(slice, dest);
		},
		else => {}
	}
	return true;
}

pub fn compile_and_load(contents: []u8, addr: u64) void {
	const allocator = std.heap.page_allocator;
	var main_mem = std.heap.ArenaAllocator.init(allocator);
	defer main_mem.deinit();
	const mem = main_mem.allocator();
	var tokens = tokenize(&mem, contents);
	show_tokens(tokens);
	if (debug){
		std.debug.print("initial------------------------------\n", .{});
	}
	var old = vm;
	vm = VM.init();
	const program_len = metaprogram(&tokens, &mem, false, null);
	if (program_len) |len| {
		for (addr..addr+len, vm.mem[start_ip..]) |index, byte| {
			old.mem[index] = byte;
		}
	}
	vm = old;
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
	if (a == .immediate or a == .literal){
		reduce_binary_suboperator(seed, data, i, b, c);
	}
	else if (a == .dereference){
		reduce_binary_suboperator(seed+9, data, i, b, c);
	}
}

pub fn reduce_binary_suboperator(seed: u8, data: []u8, i:*u64, a: Location, b:Location) void {
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

pub fn reduce_binary_operator(seed: u8, data: []u8, i: *u64, a: Location, b: Location) void {
	if (a == .immediate or a == .literal){
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
	else if (a == .dereference){
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

const PatternDef = struct {
	name: Token,
	constructors: Pattern
};

const Pattern = Buffer(Constructor);

const Constructor = struct {
	name: Token,
	fields: Buffer(Field)
};

const Field = union(enum) {
	identifier,
	constructor: Token,
	literal: Buffer(Token),
	pattern: Pattern
};

const Arg = union(enum) {
	constructor: struct {
		name: Token,
		args: Buffer(Arg)
	},
	pattern: struct {
		field: Field,
		args: Buffer(Arg)
	},
	literal: Buffer(Token),
	name: Token,
	unique: Token
};

const Application = Buffer(Token);

const Bind = struct {
	name: Buffer(Arg),
	hoist_field: ?Field,
	hoist: ?Buffer(Token),
	expansion: Buffer(Token),
	where: Buffer(Bind),

	pub fn init(mem: *const std.mem.Allocator) Bind {
		return Bind{
			.name = Buffer(Arg).init(mem.*),
			.hoist_field = null,
			.hoist = null,
			.expansion = Buffer(Token).init(mem.*),
			.where = Buffer(Bind).init(mem.*)
		};
	}
};

const State = struct {
	binds: Buffer(Bind),
	patterns: std.StringHashMap(PatternDef),
	constructors: std.StringHashMap(Constructor),
	program: Buffer(Token),

	pub fn init(mem: *const std.mem.Allocator) State {
		return State{
			.binds = Buffer(Bind).init(mem.*),
			.patterns = std.StringHashMap(PatternDef).init(mem.*),
			.constructors = std.StringHashMap(Constructor).init(mem.*),
			.program = Buffer(Token).init(mem.*)
		};
	}
};

pub fn pass_whitespace(state: *State, token_index: *u64) ParseError!void {
	while (token_index.* < state.program.items.len){
		const token = state.program.items[token_index.*];
		if (token.tag != .SPACE and token.tag != .TAB and token.tag != .NEW_LINE){
			return;
		}
		token_index.* += 1;
	}
	return ParseError.UnexpectedEOF;
}

pub fn parse_binds(mem: *const std.mem.Allocator, state: *State) ParseError!State {
	var new = State.init(mem);
	var token_index: u64 = 0;
	while (token_index < state.program.items.len){
		const token = state.program.items[token_index];
		if (token.tag == .BIND){
			const save_index = token_index;
			const bind = parse_bind(mem, state, &token_index) catch {
				new.program.append(token)
					catch unreachable;
				token_index = save_index+1;
				continue;
			};
			new.binds.append(bind)
				catch unreachable;
			continue;
		}
		else if (token.tag == .PATTERN){
			const def = try parse_pattern_def(mem, state, &token_index);
			new.patterns.put(def.name.text, def)
				catch unreachable;
			for (def.constructors.items) |cons| {
				new.constructors.put(cons.name.text, cons)
					catch unreachable;
			}
			continue;
		}
		new.program.append(token)
			catch unreachable;
		token_index += 1;
	}
	return new;
}

pub fn parse_bind(mem: *const std.mem.Allocator, state: *State, token_index: *u64) ParseError!Bind {
	try pass_whitespace(state, token_index);
	const bind_token = state.program.items[token_index.*];
	std.debug.assert(bind_token.tag == .BIND);
	token_index.* += 1;
	var bind = Bind.init(mem);
	while (token_index.* < state.program.items.len){
		try pass_whitespace(state, token_index);
		const token = state.program.items[token_index.*];
		if (token.tag == .EQUAL){
			token_index.* += 1;
			break;
		}
		bind.name.append(try parse_arg(mem, state, token_index))
			catch unreachable;
	}
	if (bind.name.items.len == 1){
		if (bind.name.items[0] == .name){
			return ParseError.UnexpectedToken;
		}
	}
	try pass_whitespace(state, token_index);
	const noteq = state.program.items[token_index.*];
	std.debug.assert(noteq.tag != .EQUAL);
	while (token_index.* < state.program.items.len){
		const token = state.program.items[token_index.*];
		if (token.tag == .HOIST){
			bind.hoist_field = try parse_field(mem, state, token_index);
			bind.hoist = bind.expansion;
			bind.expansion = Buffer(Token).init(mem.*);
			token_index.* += 1;
			continue;
		}
		if (token.tag == .SEMI) {
			token_index.* += 1;
			try pass_whitespace(state, token_index);
			const where = state.program.items[token_index.*];
			if (where.tag == .WHERE){
				token_index.* += 1;
				try pass_whitespace(state, token_index);
				const open = state.program.items[token_index.*];
				if (open.tag != .OPEN_BRACE){
					std.debug.print("Expected brace to open where clause, found {s}\n", .{open.text});
				}
				token_index.* += 1;
				while (token_index.* < state.program.items.len){
					try pass_whitespace(state, token_index);
					const next = state.program.items[token_index.*];
					if (next.tag == .CLOSE_BRACE){
						break;
					}
					bind.where.append(try parse_bind(mem, state, token_index))
						catch unreachable;
				}
			}
			return bind;
		}
		bind.expansion.append(token)
			catch unreachable;
	}
	unreachable;
}

pub fn parse_arg(mem: *const std.mem.Allocator, state: *State, token_index: *u64) ParseError!Arg {
	try pass_whitespace(state, token_index);
	const open = state.program.items[token_index.*];
	if (open.tag == .OPEN_PAREN) {
		token_index.* += 1;
		const save_index = token_index.*;
		const field = parse_field(mem, state, token_index) catch {
			token_index.* = save_index;
			try pass_whitespace(state, token_index);
			const name = state.program.items[token_index.*];
			token_index.* += 1;
			var arg = Arg {
				.constructor = .{
					.name = name,
					.args = Buffer(Arg).init(mem.*)
				}
			};
			while (token_index.* < state.program.items.len){
				try pass_whitespace(state, token_index);
				const token = state.program.items[token_index.*];
				if (token.tag == .CLOSE_PAREN){
					break;
				}
				arg.constructor.args.append(try parse_arg(mem, state, token_index))
					catch unreachable;
			}
			const token = state.program.items[token_index.*];
			std.debug.assert(token.tag != .CLOSE_PAREN);
			return arg;
		};
		var arg = Arg {
			.pattern = .{
				.field = field,
				.args = Buffer(Arg).init(mem.*)
			}
		};
		token_index.* += 1;
		while (token_index.* < state.program.items.len){
			try pass_whitespace(state, token_index);
			const token = state.program.items[token_index.*];
			if (token.tag == .CLOSE_PAREN){
				token_index.* += 1;
				break;
			}
			arg.pattern.args.append(try parse_arg(mem, state, token_index))
				catch unreachable;
		}
		const token = state.program.items[token_index.*];
		std.debug.assert(token.tag != .CLOSE_PAREN);
		token_index.* += 1;
		return arg;
	}
	else if (open.tag == .QUOTE) {
		var arg = Arg{
			.literal = Buffer(Token).init(mem.*)
		};
		token_index.* += 1;
		while (token_index.* < state.program.items.len){
			const token = state.program.items[token_index.*];
			if (token.tag == .QUOTE){
				token_index.* += 1;
				break;
			}
			arg.literal.append(token)
				catch unreachable;
			token_index.* += 1;
		}
		return arg;
	}
	else if (open.tag == .UNIQUE){
		token_index.* += 1;
		const token = state.program.items[token_index.*];
		token_index.* += 1;
		const arg = Arg{
			.unique = token
		};
		return arg;
	}
	else {
		token_index.* += 1;
		const arg = Arg {
			.name = open
		};
		return arg;
	}
	unreachable; // last clause should match any token
}

pub fn parse_field(mem: *const std.mem.Allocator, state: *State, token_index: *u64) ParseError!Field {
	try pass_whitespace(state, token_index);
	const token = state.program.items[token_index.*];
	token_index.* += 1;
	switch (token.tag){
		.ANY => {
			return Field {.identifier={}};
		},
		.QUOTE => {
			var field = Field{
				.literal=Buffer(Token).init(mem.*)
			};
			while (token_index.* != state.program.items.len){
				const innertoken = state.program.items[token_index.*];
				if (innertoken.tag == .QUOTE){
					token_index.* += 1;
					break;
				}
				field.literal.append(innertoken)
					catch unreachable;
				token_index.* += 1;
			}
			return field;
		},
		.OPEN_PAREN => {
			return Field{
				.pattern = try parse_pattern(mem, state, token_index, .CLOSE_PAREN)
			};
		},
		else => {
			return Field{
				.constructor = token
			};
		}
	}
	unreachable;
}

pub fn parse_constructor(mem: *const std.mem.Allocator, state: *State, token_index: *u64) ParseError!Constructor {
	try pass_whitespace(state, token_index);
	const name = state.program.items[token_index.*];
	if (name.tag != .IDENTIFIER){
		std.debug.print("Expected identifier for constructor name, found {s}\n", .{name.text});
		return ParseError.UnexpectedToken;
	}
	token_index.* += 1;
	var cons = Constructor{
		.name = name,
		.fields = Buffer(Field).init(mem.*)
	};
	while (token_index.* < state.program.items.len){
		try pass_whitespace(state, token_index);
		const token = state.program.items[token_index.*];
		if (token.tag == .SEMI or token.tag == .PIPE or token.tag == .CLOSE_PAREN){
			return cons;
		}
		cons.fields.append(try parse_field(mem, state, token_index))
			catch unreachable;
	}
	return cons;
}

pub fn parse_pattern(mem: *const std.mem.Allocator, state: *State, token_index: *u64, end: TOKEN) ParseError!Pattern {
	var pattern = Buffer(Constructor).init(mem.*);
	while (token_index.* < state.program.items.len){
		pattern.append(try parse_constructor(mem, state, token_index))
			catch unreachable;
		try pass_whitespace(state, token_index);
		const token = state.program.items[token_index.*];
		if (token.tag == end){
			token_index.* += 1;
			return pattern;
		}
		else if (token.tag == .PIPE){
			token_index.* += 1;
			continue;
		}
		else{
			std.debug.print("Unexpected token between pattern constructors: {s}\n", .{token.text});
			return ParseError.UnexpectedToken;
		}
	}
	unreachable;
}

pub fn parse_pattern_def(mem: *const std.mem.Allocator, state: *State, token_index: *u64) ParseError!PatternDef {
	const token = state.program.items[token_index.*];
	std.debug.assert(token.tag == .PATTERN);
	token_index.* += 1;
	try pass_whitespace(state, token_index);
	const name = state.program.items[token_index.*];
	if (name.tag != .IDENTIFIER){
		std.debug.print("Expected identifier for pattern definition name, found {s}\n", .{name.text});
		return ParseError.UnexpectedToken;
	}
	token_index.* += 1;
	try pass_whitespace(state, token_index);
	const eq = state.program.items[token_index.*];
	if (eq.tag != .EQUAL){
		std.debug.print("Expected = for pattern defintion set, found {s}\n", .{eq.text});
		return ParseError.UnexpectedToken;
	}
	token_index.* += 1;
	const def = PatternDef{
		.name=name,
		.constructors = try parse_pattern(mem, state, token_index, .SEMI)
	};
	return def;
}

pub fn show_state(state: *State) void {
	if (debug == false) {
		return;
	}
	for (state.binds.items) |*bind| {
		show_bind(bind);
	}
	var it = state.patterns.iterator();
	while (it.next()) |def| {
		show_pattern_def(&def.value_ptr.*);
		std.debug.print("\n", .{});
	}
	show_tokens(state.program);
	std.debug.print("\n", .{});
}

pub fn show_bind(bind: *Bind) void {
	if (debug == false) {
		return;
	}
	std.debug.print("bind ", .{});
	var index: u64 = 0;
	while (index < bind.name.items.len){
		show_arg(&bind.name.items[index]);
		index += 1;
	}
	std.debug.print(" =\n   ", .{});
	if (bind.hoist) |hoist| {
		show_tokens(hoist);
		std.debug.print("\n", .{});
	}
	if (bind.hoist_field) |field| {
		std.debug.print("hoisting to: ", .{});
		show_field(&field);
		std.debug.print("\n", .{});
	}
	show_tokens(bind.expansion);
	std.debug.print("\n", .{});
}

pub fn show_arg(arg: *Arg) void {
	if (debug == false) {
		return;
	}
	switch (arg.*){
		.constructor => {
			std.debug.print("( {s} ", .{arg.constructor.name.text});
			for (arg.constructor.args.items) |*a|{
				show_arg(a);
			}
			std.debug.print(") ", .{});
		},
		.pattern => {
			std.debug.print("( ", .{});
			show_field(&arg.pattern.field);
			for (arg.pattern.args.items) |*a|{
				show_arg(a);
			}
			std.debug.print(") ", .{});
		},
		.literal => {
			std.debug.print("'", .{});
			for (arg.literal.items) |tok|{
				std.debug.print("{s}", .{tok.text});
			}
			std.debug.print("' ", .{});
		},
		.name => {
			std.debug.print("{s} ", .{arg.name.text});
		},
		.unique => {
			std.debug.print("@{s} ", .{arg.unique.text});
		}
	}
}

pub fn show_field(field: *const Field) void {
	if (debug == false) {
		return;
	}
	switch (field.*){
		.identifier => {
			std.debug.print("* ", .{});
		},
		.constructor => {
			std.debug.print("{s} ", .{field.constructor.text});
		},
		.literal => {
			std.debug.print("'", .{});
			for (field.literal.items) |tok|{
				std.debug.print("{s}", .{tok.text});
			}
			std.debug.print("' ", .{});
		},
		.pattern => {
			show_pattern(&field.pattern);
		}
	}
}

pub fn show_pattern(pattern: *const Pattern) void {
	if (debug == false) {
		return;
	}
	var index: u64 = 0;
	while (index < pattern.items.len){
		if (index != 0){
			std.debug.print("| ", .{});
		}
		show_constructor(&pattern.items[index]);
		index += 1;
	}
}

pub fn show_constructor(cons: *Constructor) void {
	if (debug == false) {
		return;
	}
	std.debug.print("{s} ", .{cons.name.text});
	for (cons.fields.items) |*f| {
		show_field(f);
	}
}

pub fn show_pattern_def(def: *PatternDef) void {
	if (debug == false) {
		return;
	}
	std.debug.print("pattern {s} = ", .{def.name.text});
	show_pattern(&def.constructors);
}

pub fn parse(mem: *const std.mem.Allocator, state: *State) ParseError!State {
	var new = try parse_binds(mem, state);
	show_state(&new);
	if (debug){
		std.debug.print("initial state ----------------\n", .{});
	}
	try check_binds(&new);
	while (true){
		while (try apply_binds(mem, &new)){
			show_state(&new);
			if (debug){
				std.debug.print("applied-------------------\n", .{});
			}
		}
		if (!concat_pass(mem, &new)){
			break;
		}
		if (debug){
			std.debug.print("concatenated-------------------\n", .{});
		}
		show_state(&new);
	}
	return new;
}

pub fn check_binds(state: *State) ParseError!void {
	for (state.binds.items) |bind| {
		for (bind.name.items) |*arg| {
			try check_arg(state, arg);
		}
	}
	var it = state.constructors.iterator();
	while (it.next()) |def| {
		for (def.value_ptr.*.fields.items) |*field|{
			try check_field(state, field);
		}
	}
}

pub fn check_arg(state: *State, arg: *Arg) ParseError!void {
	switch (arg.*){
		.constructor => {
			if (state.constructors.get(arg.constructor.name.text)) |_| {
				for (arg.constructor.args.items) |*a|{
					try check_arg(state, a);
				}
			}
			else{
				std.debug.print("Unknown pattern constructor reference: {s}\n", .{arg.constructor.name.text});
				return ParseError.UnexpectedToken;
			}
		},
		.pattern => {
			try check_field(state, &arg.pattern.field);
			for (arg.pattern.args.items) |*a|{
				try check_arg(state, a);
			}
		},
		else => {
			return;
		}
	}
}

pub fn check_field(state: *State, field: *Field) ParseError!void {
	switch (field.*){
		.identifier => {
			return;
		},
		.constructor => {
			if (state.constructors.get(field.constructor.text)) |_| {}
			else{
				if (state.patterns.get(field.constructor.text)) |_| {}
				else{
					std.debug.print("Unknown constructor reference in field: {s}\n", .{field.constructor.text});
					return ParseError.UnexpectedToken;
				}
			}
		},
		.literal => {
			return;
		},
		.pattern => {
			try check_pattern(state, &field.pattern);
		}
	}
}

pub fn check_pattern(state: *State, pattern: *Pattern) ParseError!void{
	for (pattern.items) |cons|{
		for (cons.fields.items) |*field|{
			try check_field(state, field);
		}
	}
}

pub fn apply_binds(mem: *const std.mem.Allocator, state: *State) ParseError!bool {
	var bind_index:u64 = 0;
	var changed = false;
	while (bind_index < state.binds.items.len){
		const bind = &state.binds.items[bind_index];
		var token_index:u64 = 0;
		while (token_index < state.program.items.len){
			const index = token_index;
			state.program = apply_bind(mem, state, &state.program, &token_index, bind) catch {
				token_index = index + 1;
				continue;
			};
			changed = true;
		}
		var next_index:u64 = bind_index + 1;
		while (next_index < state.binds.items.len){
			const next = &state.binds.items[next_index];
			if (next.hoist) |*hoist|{
				var index:u64 = 0;
				while (index < hoist.items.len){
					const temp_index = index;
					next.hoist = apply_bind(mem, state, hoist, &index, bind) catch {
						index = temp_index + 1;
						continue;
					};
				}
			}
			var index:u64 = 0;
			while (index < next.expansion.items.len){
				const temp_index = index;
				next.expansion = apply_bind(mem, state, &next.expansion, &index, bind) catch {
					index = temp_index + 1;
					continue;
				};
			}
			next_index += 1;
		}
		bind_index += 1;
	}
	return changed;
}

pub fn apply_bind(mem: *const std.mem.Allocator, state: *State, tokens: *Buffer(Token), token_index: *u64, bind: *Bind) ParseError!Buffer(Token){
	const save_index:u64 = token_index.*;
	var new = tokens.*;
	var initial = true;
	while (true){
		var applications = std.StringHashMap(Application).init(mem.*);
		const saved_index = token_index.*;
		for (bind.name.items) |*arg| {
			const application = apply_arg(mem, state, tokens, token_index, arg, null) catch |err| {
				if (initial){
					return err;
				}
				token_index.* = saved_index;
				while (token_index.* < tokens.items.len){
					new.append(tokens.items[token_index.*])
						catch unreachable;
					token_index.* += 1;
				}
				return new;
			};
			var it = application.iterator();
			while (it.next()) |app| {
				applications.put(app.key_ptr.*, app.value_ptr.*)
					catch unreachable;
			}
		}
		new = Buffer(Token).init(mem.*);
		new.appendSlice(tokens.items[0..save_index])
			catch unreachable;
		var index:u64 = 0;
		var first = true;
		while (index < bind.expansion.items.len){
			var token = bind.expansion.items[index];
			index += 1;
			if (applications.get(token.text)) | expansion | {
				for (expansion.items) |add| {
					var copy = add;
					if (first){
						first = false;
						if (bind.hoist) |_|{
							var hoist_index:u64 = 0;
							copy.hoist_data = mem.create(Buffer(Token))
								catch unreachable;
							copy.hoist_token = mem.create(Field)
								catch unreachable;
							copy.hoist_data.?.* = try apply_bind(mem, state, &bind.hoist.?, &hoist_index, bind);
							copy.hoist_token.?.* = bind.hoist_field.?;
						}
					}
					new.append(copy)
						catch unreachable;
				}
				continue;
			}
			if (first){
				first = false;
				if (bind.hoist) |_|{
					var hoist_index:u64 = 0;
					token.hoist_data = mem.create(Buffer(Token))
						catch unreachable;
					token.hoist_token = mem.create(Field)
						catch unreachable;
					token.hoist_data.?.* = try apply_bind(mem, state, &bind.hoist.?, &hoist_index, bind);
					token.hoist_token.?.* = bind.hoist_field.?;
				}
			}
			new.append(token)
				catch unreachable;
		}
		var wherechanged = true; 
		while (wherechanged){
			wherechanged = false;
			for (bind.where.items) |*where| {
				index = save_index;
				while (index < token_index.*){
					const temp_index = index;
					new = apply_bind(mem, state, &new, &index, where) catch {
						index = temp_index + 1;
						continue;
					};
					wherechanged = true;
				}
			}
			index = save_index;
		}
		initial = false;
	}
	return new;
}

pub fn whitespace_works_out(a: *Token, b: *Token) bool {
	if ((a.tag == .WHITESPACE and b.tag == .TAB) or
		(a.tag == .WHITESPACE and b.tag == .NEW_LINE) or
		(a.tag == .WHITESPACE and b.tag == .SPACE) or
		(a.tag == .LINE_END and b.tag == .NEW_LINE)
	){
		return true;
	}
	return false;
}

pub fn apply_arg(mem: *const std.mem.Allocator, state: *State, tokens: *Buffer(Token), token_index: *u64, arg: *Arg, expected_pattern: ?Field) ParseError!std.StringHashMap(Application) {
	var applications = std.StringHashMap(Application).init(mem.*);
	switch (arg.*){
		.constructor => {
			if (state.constructors.get(arg.constructor.name.text)) |cons| {
				if (cons.fields.items.len != arg.constructor.args.items.len){
					std.debug.print("Expected {} args for {s} argument, found {}\n", .{cons.fields.items.len, arg.constructor.name.text, arg.constructor.args.items.len});
					return ParseError.UnexpectedToken;
				}
				for (arg.constructor.args.items, cons.fields.items) |*real, expected| {
					const application = try apply_arg(mem, state, tokens, token_index, real, expected);
					var it = application.iterator();
					while (it.next()) |app| {
						applications.put(app.key_ptr.*, app.value_ptr.*)
							catch unreachable;
					}
				}
				return applications;
			}
			unreachable; // should have been statically checked earlier
		},
		.pattern => {
			const application = try apply_field_binding(mem, state, tokens, token_index, &arg.pattern.field, arg.pattern.args);
			var it = application.iterator();
			while (it.next()) |app| {
				applications.put(app.key_ptr.*, app.value_ptr.*)
					catch unreachable;
			}
		},
		.literal => {
			if (expected_pattern) |exp| {
				switch (exp){
					.literal => {
						if (arg.literal.items.len != exp.literal.items.len){
							std.debug.print("Field literal and arg literal differ in length\n", .{});
							return ParseError.UnexpectedToken;
						}
						for (arg.literal.items, exp.literal.items) |*a, *e| {
							if (!token_equal(a, e)){
								return ParseError.UnexpectedToken;
							}
						}
					},
					else => {
						std.debug.print("Field not matched by literal\n", .{});
						return ParseError.UnexpectedToken;
					}
				}
			}
			for (arg.literal.items) |tok| {
				var token = tokens.items[token_index.*];
				var copy = tok;
				if (!token_equal(&copy, &token)) {
					if (!whitespace_works_out(&copy, &token)){
						return ParseError.UnexpectedToken;
					}
				}
				token_index.* += 1;
			}
		},
		.name => {
			if (expected_pattern) |exp| {
				const save:u64 = token_index.*;
				try apply_field(mem, state, tokens, token_index, &exp);
				var instance = Application.init(mem.*);
				instance.appendSlice(tokens.items[save .. token_index.*])
					catch unreachable;
				applications.put(arg.name.text, instance)
					catch unreachable;
			}
			else{
				var instance = Application.init(mem.*);
				instance.append(tokens.items[token_index.*])
					catch unreachable;
				token_index.* += 1;
				applications.put(arg.name.text, instance)
					catch unreachable;
			}
		},
		.unique => {
			var instance = Application.init(mem.*);
			instance.append(Token{.tag=.IDENTIFIER, .text=new_uid(mem), .hoist_data=null, .hoist_token = null})
				catch unreachable;
			applications.put(arg.unique.text, instance)
				catch unreachable;
			return applications;
		}
	}
	return applications;
}

pub fn apply_field(mem: *const std.mem.Allocator, state: *State, tokens: *Buffer(Token), token_index: *u64, field: *const Field) ParseError!void {
	switch (field.*){
		.identifier => {
			token_index.* += 1;
		},
		.constructor => {
			if (state.constructors.get(field.constructor.text)) |cons| {
				for (cons.fields.items) |*inner| {
					try apply_field(mem, state, tokens, token_index, inner);
				}
			}
			else if (state.patterns.get(field.constructor.text)) |def| {
				var found = false;
				const save_index = token_index.*;
				outer: for (def.constructors.items) |cons| {
					token_index.* = save_index;
					for (cons.fields.items) |*inner|{
						apply_field(mem, state, tokens, token_index, inner) catch {
							continue :outer;
						};
					}
					found = true;
					break;
				}
				if (found == false){
					return ParseError.UnexpectedToken;
				}
			}
		},
		.literal => {
			for (field.literal.items) |tok| {
				if (token_index.* >= tokens.items.len){
					return ParseError.UnexpectedToken;
				}
				var token = tokens.items[token_index.*];
				var copy = tok;
				if (!token_equal(&copy, &token)){
					if (!whitespace_works_out(&copy, &token)){
						return ParseError.UnexpectedToken;
					}
				}
				token_index.* += 1;
			}
		},
		.pattern => {
			outer: for (field.pattern.items) |cons| {
				for (cons.fields.items) |*inner| {
					apply_field(mem, state, tokens, token_index, inner) catch {
						continue :outer;
					};
				}
				return;
			}
			return ParseError.UnexpectedToken;
		}
	}
}

pub fn apply_field_binding(mem: *const std.mem.Allocator, state: *State, tokens: *Buffer(Token), token_index: *u64, field: *Field, args: Buffer(Arg)) ParseError!std.StringHashMap(Application) {
	var applications = std.StringHashMap(Application).init(mem.*);
	switch (field.*){
		.identifier => {
			if (args.items.len > 1){
				return ParseError.UnexpectedToken;
			}
			if (args.items[0] != .name){
				return ParseError.UnexpectedToken;
			}
			const token = tokens.items[token_index.*];
			var instance = Application.init(mem.*);
			instance.append(token)
				catch unreachable;
			applications.put(args.items[0].name.text, instance)
				catch unreachable;
			token_index.* += 1;
			return applications;
		},
		.constructor => {
			if (state.constructors.get(field.constructor.text)) |cons| {
				if (cons.fields.items.len != args.items.len){
					return ParseError.UnexpectedToken;
				}
				for (cons.fields.items, args.items) |inner, *arg| {
					const application = try apply_arg(mem, state, tokens, token_index, arg, inner);
					var it = application.iterator();
					while (it.next()) |app| {
						applications.put(app.key_ptr.*, app.value_ptr.*)
							catch unreachable;
					}
				}
				return applications;
			}
			else if (state.patterns.get(field.constructor.text)) |def| {
				var found = false;
				const save_index = token_index.*;
				outer: for (def.constructors.items) |cons| {
					token_index.* = save_index;
					if (cons.fields.items.len != args.items.len){
						return ParseError.UnexpectedToken;
					}
					for (cons.fields.items, args.items) |inner, *arg| {
						const application = apply_arg(mem, state, tokens, token_index, arg, inner) catch {
							continue :outer;
						};
						var it = application.iterator();
						while (it.next()) |app| {
							applications.put(app.key_ptr.*, app.value_ptr.*)
								catch unreachable;
						}
					}
					found = true;
					break;
				}
				if (found == false){
					return ParseError.UnexpectedToken;
				}
				return applications;
			}
			unreachable;
		},
		.literal => {
			if (args.items.len > 1){
				return ParseError.UnexpectedToken;
			}
			if (args.items[0] != .name){
				return ParseError.UnexpectedToken;
			}
			const save = token_index.*;
			for (field.literal.items) |tok| {
				var token = tokens.items[token_index.*];
				var copy = tok;
				if (!token_equal(&copy, &token)){
					if (!whitespace_works_out(&copy, &token)){
						return ParseError.UnexpectedToken;
					}
				}
				token_index.* += 1;
			}
			var instance = Application.init(mem.*);
			instance.appendSlice(tokens.items[save..token_index.*])
				catch unreachable;
			applications.put(args.items[0].name.text, instance)
				catch unreachable;
			return applications;
		},
		.pattern => {
			outer: for (field.pattern.items) |cons| {
				const save = token_index.*;
				for (cons.fields.items) |*inner| {
					apply_field(mem, state, tokens, token_index, inner) catch {
						token_index.* = save;
						continue :outer;
					};
				}
				for (cons.fields.items) |*inner| {
					try apply_field(mem, state, tokens, token_index, inner);
				}
				return applications;
			}
			return ParseError.UnexpectedToken;
		}
	}
	return applications;
}

pub fn concat_pass(mem: *const std.mem.Allocator, state: *State) bool {
	var changed = false;
	var token_index: u64 = 0;
	var new = Buffer(Token).init(mem.*);
	while (token_index < state.program.items.len){
		const token = state.program.items[token_index];
		token_index += 1;
		if (token_index == state.program.items.len){
			new.append(token)
				catch unreachable;
			break;
		}
		const cat = state.program.items[token_index];
		if (cat.tag == .CONCAT){
			changed = true;
			token_index += 1;
			const right = state.program.items[token_index];
			token_index += 1;
			const together = mem.alloc(u8, token.text.len + right.text.len)
				catch unreachable;
			var i:u64 = 0;
			while (i<token.text.len){
				together[i] = token.text[i];
				i += 1;
			}
			while ((i-token.text.len)<right.text.len) {
				together[i] = right.text[i-token.text.len];
				i += 1;
			}
			new.append(Token{.tag=.IDENTIFIER, .text=together, .hoist_data=token.hoist_data, .hoist_token=token.hoist_token})
				catch unreachable;
			continue;
		}
		new.append(token)
			catch unreachable;
	}
	state.program = new;
	return changed;
}

//TODO think about debugging infrastructure
//TODO introduce propper debugger state
	//breakpoints
	//stepthrough
	//backtrack
//TODO memory optimization with aux buffers

//TODO differentiate run bind parsing somehow

