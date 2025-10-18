const std = @import("std");
const rl = @import("raylib");
const Buffer = std.ArrayList;

var debug:bool = false;
var debug_comp:bool = false;

var error_index:u64 = 0;
var error_buffer: [512]u8 = undefined;
var error_buffer_len: u64 = 0;
var error_token: ?Token = null;

var uid: []const u8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

var iden_hashes = std.StringHashMap(u64).init(std.heap.page_allocator);
var current_iden: u64 = 0x0000000100000000;

var persistent = std.StringHashMap(u64).init(std.heap.page_allocator);
var comp_persistent = std.StringHashMap(u64).init(std.heap.page_allocator);
var comp_section = false;

const frame_buffer_w = 320;
const pixel_width = 4;
const word_size = 8;
const frame_buffer_h = 180;

const cores = 1;
threadlocal var active_core: u64 = 0;
var threads: [cores]std.Thread = undefined;
var thread_mutex = std.Thread.Mutex{};
var cores_running: u64 = 0; // atomic
var kill_cores = false;

const frame_buffer = frame_buffer_w*frame_buffer_h*pixel_width;
const mem_size = 0x100000;
const main_size = mem_size+frame_buffer;
const register_section = word_size*6*cores;
const start_ip = frame_buffer;
const total_mem_size = frame_buffer+mem_size+register_section;

const VM = struct {
	mem: [total_mem_size]u8,
	words: []align(1) u64,
	half_words: []align(1) u32,
	r0: [cores]u64,
	r1: [cores]u64,
	r2: [cores]u64,
	r3: [cores]u64,
	sr: [cores]u64,
	ip: [cores]u64,
	
	pub fn init() VM {
		var mach = VM{
			.mem=undefined,
			.words=undefined,
			.half_words=undefined,
			.r0=undefined,
			.r1=undefined,
			.r2=undefined,
			.r3=undefined,
			.sr=undefined,
			.ip=undefined,
		};
		var offset:u64 = 0;
		for (0..cores) |i| {
			mach.r0[i] = main_size+offset*8;
			offset += 1;
			mach.r1[i] = main_size+offset*8;
			offset += 1;
			mach.r2[i] = main_size+offset*8;
			offset += 1;
			mach.r3[i] = main_size+offset*8;
			offset += 1;
			mach.sr[i] = main_size+offset*8;
			offset += 1;
			mach.ip[i] = main_size+offset*8;
			offset += 1;
		}
		return mach;
	}
};

var vm: VM = VM.init();
var pass_vm: VM = VM.init();

var frame_buffer_image = rl.Image{
	.data=&vm.mem[0],
	.width=frame_buffer_w,
	.height=frame_buffer_h,
	.mipmaps=1,
	.format=rl.PixelFormat.uncompressed_r8g8b8a8
};

var frame_buffer_texture:rl.Texture = undefined;

pub fn main() !void {
	partition_vm();
	push_builtin_constants();
	std.debug.assert(total_mem_size % 8 == 0);
	const allocator = std.heap.page_allocator;
	const args = try std.process.argsAlloc(allocator);
	if (std.mem.eql(u8, args[1], "-h")){
		std.debug.print("Help Menu\n", .{});
		std.debug.print("    -h             :  show this message\n", .{});
		std.debug.print("    -g             :  activate runtime debug mode\n", .{});
		std.debug.print("    -gc            :  activate comptime debug mode\n", .{});
		std.debug.print("    -c             :  Prevent running the program\n", .{});
		std.debug.print("    [filename]     :  compile and run src program\n", .{});
		std.debug.print("    -o [filename]  :  compile src program to binary\n", .{});
		std.debug.print("    -p [filename]  :  compile src program as a plugin\n", .{});
		std.debug.print("    -i [filename]  :  run compiled src program\n", .{});
		return;
	}
	var arg_index:u64 = 0;
	var filename: ?[]u8 = null;
	var input_filename: ?[]u8 = null;
	var output_filename: ?[]u8 = null;
	var expansion_filename: ?[]u8 = null;
	var run = true;
	while (arg_index < args.len){
		const arg = args[arg_index];
		arg_index += 1;
		if (std.mem.eql(u8, arg, "-g")){
			debug = true;
			continue;
		}
		if (std.mem.eql(u8, arg, "-gc")){
			debug_comp = true;
			continue;
		}
		if (std.mem.eql(u8, arg, "-i")){
			if (arg_index == args.len){
				std.debug.print("Expected filename for input\n", .{});
				return;
			}
			input_filename = args[arg_index];
			arg_index += 1;
			continue;
		}
		if (std.mem.eql(u8, arg, "-o")){
			if (arg_index == args.len){
				std.debug.print("Expected filename for output\n", .{});
				return;
			}
			output_filename = args[arg_index];
			arg_index += 1;
			continue;
		}
		if (std.mem.eql(u8, arg, "-p")){
			if (arg_index == args.len){
				std.debug.print("Expected filename for expansion output\n", .{});
				return;
			}
			expansion_filename = args[arg_index];
			arg_index += 1;
			continue;
		}
		if (std.mem.eql(u8, arg, "-c")){
			run = false;
		}
		filename = arg;
	}
	if (input_filename) |infile| {
		var thread_index: u64 = 0;
		while (thread_index < threads.len){
			threads[thread_index] = std.Thread.spawn(.{}, core_worker, .{thread_index}) catch unreachable;
			thread_index += 1;
		}
		run_file(infile);
		thread_index = 0;
		while (thread_index < threads.len){
			threads[thread_index].join();
			thread_index += 1;
		}
		return;
	}
	if (filename) |name| {
		var thread_index: u64 = 0;
		while (thread_index < threads.len){
			threads[thread_index] = std.Thread.spawn(.{}, core_worker, .{thread_index}) catch unreachable;
			thread_index += 1;
		}
		compile(name, output_filename, expansion_filename, run);
		thread_index = 0;
		while (thread_index < threads.len){
			threads[thread_index].join();
			thread_index += 1;
		}
	}
	else{
		std.debug.print("Provide head filename\n", .{});
	}
}

pub fn core_worker(index: u64) void {
	active_core = index;
	while (!kill_cores){
		if (vm.words[vm.ip[active_core]>>3] == 0){
			std.time.sleep(1_000_000); // 1ms
			continue;
		}
		interpret(vm.words[vm.ip[active_core]>>3]);
	}
}

pub fn awaken_core(new_ip: u64) u64 {
	thread_mutex.lock();
	defer thread_mutex.unlock();
	for (vm.ip, 1..) |ip, i| {
		if (vm.words[ip>>3] == 0){
			vm.words[ip>>3] = new_ip;
			_ = @atomicRmw(u64, &cores_running, .Add, 1, .seq_cst);
			if (debug){
				std.debug.print("awoke {}\n", .{i});
			}
			return i;
		}
	}
	return 0;
}

pub fn sleep_core() void {
	thread_mutex.lock();
	defer thread_mutex.unlock();
	vm.words[vm.ip[active_core]>>3] = 0;
	_ = @atomicRmw(u64, &cores_running, .Sub, 1, .seq_cst);
	if (debug){
		std.debug.print("slept {}\n", .{active_core+1});
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

pub fn compile(filename: []u8, output_filename: ?[]u8, expand_filename: ?[]u8, run: bool) void {
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
	if (expand_filename) |outfilename| {
		_ = metaprogram(&tokens, &mem, false, outfilename);
	}
	const program_len = metaprogram(&tokens, &mem, run, null);
	if (program_len) |len| {
		if (output_filename) |outfilename|{
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
	const core = awaken_core(start_ip);
	std.debug.assert(core != 0);
	await_cores();
	kill_cores = true;
}

pub fn await_cores() void {
	while (@atomicLoad(u64, &cores_running, .seq_cst) != 0){
		std.time.sleep(1_000_000); // 1ms
	}
	if (debug) {
		std.debug.print("All cores done\n", .{});
	}
}

pub fn metaprogram(tokens: *Buffer(Token), mem: *const std.mem.Allocator, run: bool, headless: ?[]u8) ?u64 {
	const allocator = std.heap.page_allocator;
	var main_aux = std.heap.ArenaAllocator.init(allocator);
	var main_txt = std.heap.ArenaAllocator.init(allocator);
	defer main_aux.deinit();
	defer main_txt.deinit();
	const token_stream = import_flatten(mem, tokens) catch |err| {
		std.debug.print("Error flattening imports: {}\n", .{err});
		return null;
	};
	show_tokens(token_stream.*);
	if (debug){
		std.debug.print("flattened-------------------------------\n", .{});
	}
	var new_stream = parse_pass(mem, token_stream.*) catch |err| {
		std.debug.print("Parse pass error: {}\n", .{err});
		report_error(token_stream.*, null);
		return null;
	};
	var index:u64 = 0;
	if (headless) |filename| {
		const stream = parse_plugin(mem, &new_stream, &index, false) catch |err| {
			std.debug.print("Headless Plugin Parse Error: {} \n", .{err});
			report_error(token_stream.*, new_stream);
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
	const program_len = parse_bytecode(mem, runtime.mem[start_ip..], &new_stream, &index, false) catch |err| {
		std.debug.print("Bytecode Parse Error {}\n", .{err});
		report_error(token_stream.*, new_stream);
		return null;
	};
	vm = runtime;
	partition_vm();
	if (run){
		if (debug){
			std.debug.print("program length: {}\n", .{program_len});
			std.debug.print("parsed bytecode--------------------\n", .{});
		}
		const core = awaken_core(start_ip);
		std.debug.assert(core != 0);
		await_cores();
		kill_cores = true;
	}
	return program_len;
}

pub fn import_flatten(mem: *const std.mem.Allocator, input_tokens: *Buffer(Token)) ParseError!*Buffer(Token) {
	var tokens = input_tokens;
	const allocator = std.heap.page_allocator;
	var new = mem.create(Buffer(Token)) catch {
		set_error(0, null, "could not allocate aux buffer for import flatten\n", .{});
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
					set_error(token_index-1, filename, "Unable to allocate filename {s}{s}\n", .{filename.text, ".src"});
					return ParseError.FileError;
				};
				var file = std.fs.cwd().openFile(infile, .{}) catch {
					set_error(token_index-1, filename, "File not found: {s}\n", .{infile});
					return ParseError.FileNotFound;
				};
				defer file.close();
				const stat = file.stat() catch {
					std.debug.print("Broken file stat: {s}\n", .{infile});
					return ParseError.FileNotFound;
				};
				const contents = file.readToEndAlloc(allocator, stat.size+1) catch {
					set_error(token_index-1, filename, "Error reading file: {s}\n", .{infile});
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
	BIND, COMP_START, COMP_END, PASS_START, PASS_END,
	OPEN_BRACK, CLOSE_BRACK,
	USING,
	IDENTIFIER,
	LIT,
	MOV, MOVL, MOVH, MOVW,
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
	line: u64,
	source_index: u64,
};

pub fn tokenize(mem: *const std.mem.Allocator, text: []u8) Buffer(Token) {
	var i: u64 = 0;
	var token_map = std.StringHashMap(TOKEN).init(mem.*);
	token_map.put("bind", .BIND) catch unreachable;
	token_map.put("pass", .PASS_START) catch unreachable;
	token_map.put("end", .PASS_END) catch unreachable;
	token_map.put("using_opinion", .USING) catch unreachable;
	var tokens = Buffer(Token).init(mem.*);
	var line: u64 = 1;
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
				'\n' => {
					line += 1;
					break :blk .NEW_LINE;
				},
				'[' => {break :blk .OPEN_BRACK;},
				']' => {break :blk .CLOSE_BRACK;},
				'$' => {break :blk .LINE_END;},
				'%' => {break :blk .WHITESPACE;},
				'!' => {break :blk .LIT;},
				else => {break :blk .IDENTIFIER;}
			}
			break :blk .IDENTIFIER;
		};
		if (tag != .IDENTIFIER){
			if (escape){
				tag = .IDENTIFIER;
			}
			tokens.append(Token{
				.tag=tag,
				.text=text[i..i+1],
				.line = line,
				.source_index = tokens.items.len
			})
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
		tokens.append(Token{
			.tag=tag,
			.text=keyword,
			.line = line,
			.source_index = tokens.items.len
		})
			catch unreachable;
		i += size;
	}
	return tokens;
}

pub fn retokenize(mem: *const std.mem.Allocator, tokens: *const Buffer(Token)) ParseError!void {
	var token_map = std.StringHashMap(TOKEN).init(mem.*);
	token_map.put("comp", .COMP_START) catch unreachable;
	token_map.put("run", .COMP_END) catch unreachable;
	token_map.put("pass", .PASS_START) catch unreachable;
	token_map.put("end", .PASS_END) catch unreachable;
	token_map.put("mov", .MOV) catch unreachable;
	token_map.put("movl", .MOVL) catch unreachable;
	token_map.put("movh", .MOVH) catch unreachable;
	token_map.put("movw", .MOVW) catch unreachable;
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
	token_map.put("!", .LIT) catch unreachable;
	token_map.put("[", .OPEN_BRACK) catch unreachable;
	token_map.put("]", .CLOSE_BRACK) catch unreachable;
	for (tokens.items) |*token| {
		if (token_map.get(token.text)) |tag| {
			token.tag = tag;
		}
	}
}

pub fn show_tokens(tokens: Buffer(Token)) void {
	if (!debug){
		return;
	}
	for (tokens.items) |*token| {
		std.debug.print("{s}", .{token.text});
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
	set_error(token_index.*, tokens[tokens.len-1], "Encountered end of file in whitespace skip\n", .{});
	return ParseError.UnexpectedEOF;
}

pub fn report_error(original: Buffer(Token), current: ?Buffer(Token)) void {
	const stderr = std.io.getStdErr().writer();
	stderr.print("{s}\n", .{error_buffer[0..error_buffer_len]}) catch unreachable;
	var line:u64 = 1;
	var offset:u64 = 8;
	if (error_index < offset){
		offset = error_index-1;
	}
	if (error_token) |tok| {
		var token_index: u64 = 0;
		if (current) |expansion|{
			std.debug.print("In expansion: \n", .{});
			while (token_index < expansion.items.len){
				const token = expansion.items[token_index];
				token_index += 1;
				if (token_index-1 > error_index - offset and token_index-1 < error_index + 8){
					if (token_index-1 == error_index){
						stderr.print("\x1b[4m{s}\x1b[0m", .{token.text}) catch unreachable;
					}
					else{
						stderr.print("{s}", .{token.text}) catch unreachable;
					}
				}
				if (token_index > error_index - offset and token_index < error_index + 8){
					if (token.tag == .NEW_LINE){
						line += 1;
						stderr.print("{d:06} | ", .{line}) catch unreachable;
					}
				}
			}
			std.debug.print("\n", .{});
		}
		if (tok.line == 0 or tok.source_index == 0){
			return;
		}
		stderr.print("\nIn source: \n", .{}) catch unreachable;
		token_index = 0;
		line = 1;
		while (token_index < original.items.len){
			const token = original.items[token_index];
			token_index += 1;
			if (line > tok.line-2 and line < tok.line + 2){
				if (token_index-1 == tok.source_index){
					stderr.print("\x1b[4m{s}\x1b[0m", .{token.text}) catch unreachable;
				}
				else{
					stderr.print("{s}", .{token.text}) catch unreachable;
				}
			}
			if (token.tag == .NEW_LINE){
				line += 1;
				if (line > tok.line-2 and line < tok.line + 2){
					stderr.print("{d:06} | ", .{line}) catch unreachable;
				}
			}
		}
	}
	stderr.print("\n", .{}) catch unreachable;
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
	return Token{
		.tag=.IDENTIFIER,
		.text=slice,
		.line = 0,
		.source_index = 0
	};
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
		movew: struct {
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
			set_error(token_index.*-1, tokens.items[tokens.items.len-1],"Expected opcode, found end of file\n", .{});
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
				const core = awaken_core(start_ip);
				std.debug.assert(core != 0);
				await_cores();
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
					set_error(token_index.*-1, name, "Expected name for transfer bind, found {s}\n", .{name.text});
					return ParseError.UnexpectedToken;
				}
				skip_whitespace(tokens.items, token_index) catch {
					return output;
				};
				const comp_stack = comp_section;
				comp_section = true;
				const loc = try parse_location(mem, tokens, token_index);
				comp_section = comp_stack;
				const val = val64(loc) catch {
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
				set_error(token_index.*-1, tokens.items[tokens.items.len-1], "Expected opcode, found end of file\n", .{});
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
						const core = awaken_core(start_ip);
						std.debug.assert(core != 0);
						await_cores();
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
						set_error(token_index.*-1, name, "Expected name for transfer bind, found {s}\n", .{name.text});
						return ParseError.UnexpectedToken;
					}
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
					const val = val64(loc) catch {
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
				.MOVW => {
					op = Instruction{
						.tag=.movw_i,
						.data=.{
							.movew=.{
								.dest = try parse_location_or_label(mem, tokens, token_index, labels, false),
								.src = try parse_location_or_label(mem, tokens, token_index, labels, false)
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
					set_error(token_index.*-1, token, "Expected opcode, found {s}\n", .{token.text});
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
				.movew => {
					const dest = reduce_location(&inst.data.movew.dest);
					const src = reduce_location(&inst.data.movew.src);
					var offset:u32 = 0;
					switch (dest){
						.immediate => {
							offset = 0;
						},
						.literal => {
							offset = 1;
						},
						.dereference => {
							offset = 2;
						},
						.register => {
							unreachable;
						}
					}
					store_u32(data, i, @intFromEnum(inst.tag)+offset);
					i += 4;
					write_location(data, &i, dest);
					write_location_64(data, &i, src);
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
					reduce_binary_operator_extended(@intFromEnum(inst.tag), data, &i, left, right);
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
		set_error(token_index.*-1, tokens.items[tokens.items.len-1], "Expected operand for instruction, found end of file\n", .{});
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
				set_error(token_index.*, tokens.items[token_index.*], "Expected close bracket for dereferenced location\n", .{});
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
				if (token.tag == .WHITESPACE or token.tag == .LINE_END){
					return Location {
						.literal = hash_global_enum(token)
					};
				}
				set_error(token_index.*-1, token, "Expected indentifier to serve as immediate value, found {s}\n", .{token.text});
				return ParseError.UnexpectedToken;
			}
			return Location{
				.literal = hash_global_enum(token)
			};
		},
		else => {
			set_error(token_index.*, token, "Expected operand, found {s}\n", .{token.text});
			return ParseError.UnexpectedToken;
		}
	}
}

pub fn parse_location(mem: *const std.mem.Allocator, tokens: *const Buffer(Token), token_index: *u64) ParseError!Location {
	try skip_whitespace(tokens.items, token_index);
	if (token_index.* > tokens.items.len){
		set_error(token_index.*-1, tokens.items[tokens.items.len-1], "Expected operand for instruction, found end of file\n", .{});
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
			set_error(token_index.*-1, tokens.items[token_index.*], "Expected close bracket for dereferenced location\n", .{});
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
				set_error(token_index.*-1, token, "Expected indentifier to serve as immediate value, found {s}\n", .{token.text});
				return ParseError.UnexpectedToken;
			}
			return Location{
				.literal = hash_global_enum(token)
			};
		},
		else => {
			set_error(token_index.*, token, "Expected operand, found {s}\n", .{token.text});
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
				.R0 => {store_u64(vm.r0[active_core], val);},
				.R1 => {store_u64(vm.r1[active_core], val);},
				.R2 => {store_u64(vm.r2[active_core], val);},
				.R3 => {store_u64(vm.r3[active_core], val);},
				.IP => {store_u64(vm.ip[active_core], val);},
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
				.R0 => {return load_u64(vm.r0[active_core]);},
				.R1 => {return load_u64(vm.r1[active_core]);},
				.R2 => {return load_u64(vm.r2[active_core]);},
				.R3 => {return load_u64(vm.r3[active_core]);},
				.IP => {return load_u64(vm.r3[active_core]);},
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
	movw_i, movw_l, movw_d,
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

pub fn partition_vm() void {
	vm.words = std.mem.bytesAsSlice(u64, vm.mem[0..]);
	vm.half_words = std.mem.bytesAsSlice(u32, vm.mem[0..]);
}

pub fn interpret(start:u64) void {
	if (!rl.isWindowReady()){
		rl.initWindow(frame_buffer_w, frame_buffer_h, "src");
		frame_buffer_texture = rl.loadTextureFromImage(frame_buffer_image) catch unreachable;
	}
	const ip = &vm.words[vm.ip[active_core]/8];
	ip.* = start/8;
	const ops: [236]OpBytesFn = .{
		mov_ii_bytes, mov_il_bytes, mov_id_bytes, mov_di_bytes, mov_dl_bytes, mov_dd_bytes,
		movw_i_bytes, movw_l_bytes, movw_d_bytes,
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
		if ((!comp_section and debug) or (comp_section and debug_comp)){
			const stdout = std.io.getStdOut().writer();
			stdout.print("\x1b[2J\x1b[H", .{}) catch unreachable;
			debug_show_instruction_ref_path(vm.words[vm.ip[active_core]/8]);
			debug_show_instruction_ref_path(vm.words[vm.ip[active_core]/8]-2);
			stdout.print("\x1b[H", .{}) catch unreachable;
			debug_show_registers();
			debug_show_instructions();
			stdout.print("[core {}]\n", .{active_core}) catch unreachable;
			var stdin = std.io.getStdIn().reader();
			var buffer: [1]u8 = undefined;
			_ = stdin.read(&buffer) catch unreachable;
		}
		running = ops[vm.words[ip.*]&0xFFFFFFFF](ip);
	}
}

pub fn debug_show_registers() void {
	const stdout = std.io.getStdOut().writer();
	stdout.print(",---------------------.\n", .{}) catch unreachable;
	stdout.print("| r0: {x:016} |\n", .{vm.words[vm.r0[active_core]/8]}) catch unreachable;
	stdout.print("| r1: {x:016} |\n", .{vm.words[vm.r1[active_core]/8]}) catch unreachable;
	stdout.print("| r2: {x:016} |\n", .{vm.words[vm.r2[active_core]/8]}) catch unreachable;
	stdout.print("| r3: {x:016} |\n", .{vm.words[vm.r3[active_core]/8]}) catch unreachable;
	stdout.print("| \x1b[1;31mip: {x:016}\x1b[0m |\n", .{vm.words[vm.ip[active_core]/8]*8}) catch unreachable;
	stdout.print("`----------------------'\n\n\n\n", .{}) catch unreachable;
}

pub fn debug_show_instructions() void {
	const stdout = std.io.getStdOut().writer();
	stdout.print(",-----------------------------------------------------.\n", .{}) catch unreachable;
	var inst_start = vm.words[vm.ip[active_core]/8];
	if (inst_start < 16){
		inst_start = 0;
	}
	else {
		inst_start -= 16;
	}
	const inst_end = inst_start+32;
	while (inst_start < inst_end): (inst_start += 2){
		stdout.print("| ", .{}) catch unreachable;
		if (inst_start == vm.words[vm.ip[active_core]/8]){
			stdout.print("\x1b[1;31m", .{}) catch unreachable;
		}
		stdout.print("{x:016}: {x:016} {x:016}", .{inst_start*8, vm.words[inst_start], vm.words[inst_start+1]}) catch unreachable;
		if (inst_start == vm.words[vm.ip[active_core]/8]){
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
	if (ref/8 < vm.words.len){
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

pub fn movw_i_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const reg_chunk = vm.words[p];
	const arg = vm.words[p+1];
	const loc = reg_chunk >> 32;
	vm.words[loc >> 3] = arg;
	return true;
}

pub fn movw_l_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const reg_chunk = vm.words[p];
	const arg = vm.words[p+1];
	const reg = reg_chunk >> 32;
	vm.words[reg >> 3] = arg;
	return true;
}

pub fn movw_d_bytes(ip: *align(1) u64) bool {
	const p = ip.*;
	ip.* += 2;
	const reg_chunk = vm.words[p];
	const arg = vm.words[p+1];
	const loc_name = reg_chunk >> 32;
	const loc = vm.words[loc_name >> 3];
	vm.words[loc >> 3] = arg;
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
		vm.mem[vm.sr[active_core]] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr[active_core]] = 2;
	}
	else {
		vm.mem[vm.sr[active_core]] = 0;
	}
	ip.* += 2;
	return true;
}

pub fn cmp_il_bytes(ip: *align(1) u64) bool {
	const args = vm.words[ip.*+1];
	const left_name = (args & 0xFFFFFFFF);
	const right = args >> 32;
	const left = vm.words[left_name >> 3];
	if (left > right){
		vm.mem[vm.sr[active_core]] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr[active_core]] = 2;
	}
	else {
		vm.mem[vm.sr[active_core]] = 0;
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
		vm.mem[vm.sr[active_core]] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr[active_core]] = 2;
	}
	else {
		vm.mem[vm.sr[active_core]] = 0;
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
		vm.mem[vm.sr[active_core]] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr[active_core]] = 2;
	}
	else {
		vm.mem[vm.sr[active_core]] = 0;
	}
	ip.* += 2;
	return true;
}

pub fn cmp_ll_bytes(ip: *align(1) u64) bool {
	const args = vm.words[ip.*+1];
	const left = (args & 0xFFFFFFFF);
	const right = args >> 32;
	if (left > right){
		vm.mem[vm.sr[active_core]] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr[active_core]] = 2;
	}
	else {
		vm.mem[vm.sr[active_core]] = 0;
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
		vm.mem[vm.sr[active_core]] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr[active_core]] = 2;
	}
	else {
		vm.mem[vm.sr[active_core]] = 0;
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
		vm.mem[vm.sr[active_core]] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr[active_core]] = 2;
	}
	else {
		vm.mem[vm.sr[active_core]] = 0;
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
		vm.mem[vm.sr[active_core]] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr[active_core]] = 2;
	}
	else {
		vm.mem[vm.sr[active_core]] = 0;
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
		vm.mem[vm.sr[active_core]] = 1;
	}
	else if (left < right){
		vm.mem[vm.sr[active_core]] = 2;
	}
	else {
		vm.mem[vm.sr[active_core]] = 0;
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
	if (vm.mem[vm.sr[active_core]] != 0){
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
	if (vm.mem[vm.sr[active_core]] != 0){
		const label = vm.words[ip.*+1] >> 32;
		ip.* = label;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jne_d_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr[active_core]] != 0){
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
	if (vm.mem[vm.sr[active_core]] == 0){
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
	if (vm.mem[vm.sr[active_core]] == 0){
		const label = vm.words[ip.*+1] >> 32;
		ip.* = label;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jeq_d_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr[active_core]] == 0){
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
	if (vm.mem[vm.sr[active_core]] == 1){
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
	if (vm.mem[vm.sr[active_core]] == 1){
		const label = vm.words[ip.*+1] >> 32;
		ip.* = label;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jgt_d_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr[active_core]] == 1){
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
	if (vm.mem[vm.sr[active_core]] != 2){
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
	if (vm.mem[vm.sr[active_core]] != 2){
		const label = vm.words[ip.*+1] >> 32;
		ip.* = label;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jge_d_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr[active_core]] != 2){
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
	if (vm.mem[vm.sr[active_core]] == 2){
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
	if (vm.mem[vm.sr[active_core]] == 2){
		const label = vm.words[ip.*+1] >> 32;
		ip.* = label;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jlt_d_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr[active_core]] == 2){
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
	if (vm.mem[vm.sr[active_core]] != 1){
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
	if (vm.mem[vm.sr[active_core]] != 1){
		const label = vm.words[ip.*+1] >> 32;
		ip.* = label;
	}
	else {
		ip.* += 2;
	}
	return true;
}

pub fn jle_d_bytes(ip: *align(1) u64) bool {
	if (vm.mem[vm.sr[active_core]] != 1){
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
	switch (vm.mem[vm.r0[active_core]]){
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
			sleep_core();
			return false;
		},
		2 => {
			std.debug.print("{c}", .{vm.mem[vm.r1[active_core]]});
			return true;
		},
		3 => {
			if (rl.isKeyDown(@enumFromInt(vm.words[vm.r1[active_core]/8]))){
				vm.mem[vm.r2[active_core]] = 1;
				return true;
			}
			vm.mem[vm.r2[active_core]] = 0;
			return true;
		},
		4 => {
			if (rl.isKeyPressed(@enumFromInt(vm.words[vm.r1[active_core]/8]))){
				vm.mem[vm.r2[active_core]] = 1;
				return true;
			}
			vm.mem[vm.r2[active_core]] = 0;
			return true;
		},
		5 => {
			const mp = rl.getMousePosition();
			vm.mem[vm.r1[active_core]] = @intFromFloat(mp.x);
			vm.mem[vm.r2[active_core]] = @intFromFloat(mp.y);
			return true;
		},
		6 => {
			if (rl.isMouseButtonDown(@enumFromInt(vm.words[vm.r1[active_core]/8]))){
				vm.mem[vm.r2[active_core]] = 1;
				return true;
			}
			vm.mem[vm.r2[active_core]] = 0;
			return true;
		},
		7 => {
			if (rl.isMouseButtonPressed(@enumFromInt(vm.words[vm.r1[active_core]/8]))){
				vm.mem[vm.r2[active_core]] = 1;
				return true;
			}
			vm.mem[vm.r2[active_core]] = 0;
			return true;
		},
		8 => {
			const addr = vm.mem[vm.r1[active_core]];
			const len = vm.mem[vm.r2[active_core]];
			const dest = vm.mem[vm.r3[active_core]];
			const slice = vm.mem[addr..addr+len];
			compile_and_load(slice, dest);
		},
		9 => {
			const new_ip = vm.mem[vm.r1[active_core]];
			const core = awaken_core(new_ip);
			vm.words[vm.r0[active_core]>>3] = core;
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
	partition_vm();
	const program_len = metaprogram(&tokens, &mem, false, null);
	if (program_len) |len| {
		for (addr..addr+len, vm.mem[start_ip..]) |index, byte| {
			old.mem[index] = byte;
		}
	}
	vm = old;
	partition_vm();
}

pub fn reduce_location(loc: *Location) Location {
	switch (loc.*){
		.register => {
			switch (loc.register){
				.R0 => {
					loc.* = Location{
						.immediate = vm.r0[active_core]
					};
				},
				.R1 => {
					loc.* = Location{
						.immediate = vm.r1[active_core]
					};
				},
				.R2 => {
					loc.* = Location{
						.immediate = vm.r2[active_core]
					};
				},
				.R3 => {
					loc.* = Location{
						.immediate = vm.r3[active_core]
					};
				},
				.IP => {
					loc.* = Location{
						.immediate = vm.ip[active_core]
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

pub fn reduce_binary_operator_extended(seed: u8, data: []u8, i: *u64, a: Location, b: Location) void {
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

pub fn write_location_64(data: []u8, i: *u64, src: Location) void {
	switch (src){
		.immediate => {
			const bytes: [8]u8 = @bitCast(src.immediate);
			@memcpy(data[i.*..i.*+8], &bytes);
			i.* += 8;
		},
		.literal => {
			const bytes: [8]u8 = @bitCast(src.literal);
			@memcpy(data[i.*..i.*+8], &bytes);
			i.* += 8;
		},
		.dereference => {
			write_location_64(data, i, src.dereference.*);
		},
		.register => {
			unreachable;
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

pub fn set_error(index: u64, token: ?Token, comptime fmt: []const u8, args: anytype) void {
    const result = std.fmt.bufPrint(&error_buffer, fmt, args) catch unreachable;
    error_buffer_len = result.len;
	error_index = index;
	error_token = token;
}

pub fn parse_pass(mem: *const std.mem.Allocator, input: Buffer(Token)) ParseError!Buffer(Token) {
	pass_vm.words = std.mem.bytesAsSlice(u64, pass_vm.mem[0..]);
	pass_vm.half_words = std.mem.bytesAsSlice(u32, pass_vm.mem[0..]);
	var token_index:u64 = 0;
	var new = Buffer(Token).init(mem.*);
	var tokens = Buffer(Token).init(mem.*);
	tokens.appendSlice(input.items)
		catch unreachable;
	while (token_index < tokens.items.len){
		const token = tokens.items[token_index];
		token_index += 1;
		if (token.tag == .PASS_START){
			const start = token_index;
			var end = start;
			while (token_index < tokens.items.len){
				const inner = tokens.items[token_index];
				if (inner.tag == .PASS_END){
					end = token_index;
					token_index += 1;
					break;
				}
				token_index += 1;
			}
			var index:u64 = 0;
			var slice = Buffer(Token).init(mem.*);
			slice.appendSlice(tokens.items[start..end])
				catch unreachable;
			const program_len = try parse_bytecode(mem, pass_vm.mem[start_ip..], &slice, &index, false);
			if(debug){
				std.debug.print("pass program_len: {}\n", .{program_len});
			}
			const source_addr = start_ip+program_len;
			var source_slice = pass_vm.words[source_addr/8..];
			var source_len:u64 = 0;
			while (token_index < tokens.items.len){
				source_slice[source_len] = hash_global_enum(tokens.items[token_index]);
				token_index += 1;
				source_len += 1;
			}
			const dest_addr = start_ip+program_len+(source_len*8);
			pass_vm.words[pass_vm.r0[active_core]/8] = source_addr;
			pass_vm.words[pass_vm.r1[active_core]/8] = dest_addr;
			if (debug){
				std.debug.print("pass program dest_addr: {}\n", .{dest_addr/8});
			}
			const old_vm = vm;
			vm = pass_vm;
			partition_vm();
			comp_section = true;
			const core = awaken_core(start_ip);
			std.debug.assert(core != 0);
			await_cores();
			comp_section = false;
			const end_addr = vm.words[vm.r1[active_core]/8]/8;
			if(debug){
				std.debug.print("pass program end_addr: {}\n", .{end_addr});
			}
			var translated = Buffer(Token).init(mem.*);
			var word_index = dest_addr/8;
			var it = iden_hashes.iterator();
			var lookup: []Token = mem.alloc(Token, current_iden-0x0000000100000000) catch unreachable;
			while (it.next()) |ptr| {
				var copy = mem.alloc(u8, ptr.key_ptr.len) catch unreachable;
				for (0..copy.len) |i| {
					copy[i] = ptr.key_ptr.*[i];
				}
				if (ptr.value_ptr.* > 0xFFFFFFFF){
					if (std.mem.eql(u8, copy, " ")){
						lookup[ptr.value_ptr.*-0x100000000] = Token{
							.tag=.SPACE,
							.text=copy,
							.line=0,
							.source_index=0
						};
					}
					else if (std.mem.eql(u8, copy, "\n")){
						lookup[ptr.value_ptr.*-0x100000000] = Token{
							.tag=.NEW_LINE,
							.text=copy,
							.line=0,
							.source_index=0
						};
					}
					else if (std.mem.eql(u8, copy, "\t")){
						lookup[ptr.value_ptr.*-0x100000000] = Token{
							.tag=.TAB,
							.text=copy,
							.line=0,
							.source_index=0
						};
					}
					else{
						lookup[ptr.value_ptr.*-0x100000000] = Token{
							.tag=.IDENTIFIER,
							.text=copy,
							.line=0,
							.source_index=0
						};
					}
				}
			}
			while (word_index < end_addr){
				const enumeration = vm.words[word_index];
				word_index += 1;
				if (enumeration > 0xFFFFFFFF){
					const inst = lookup[enumeration-0x100000000];
					translated.append(inst)
						catch unreachable;
					continue;
				}
				translated.append(mk_token_from_u64(mem, enumeration))
					catch unreachable;
			}
			vm = old_vm;
			partition_vm();
			new.appendSlice(translated.items)
				catch unreachable;
			const tmp = tokens;
			tokens = new;
			token_index = 0;
			new = tmp;
			new.clearRetainingCapacity();
			continue;
		}
		new.append(token)
			catch unreachable;
	}
	return new;
}

//TODO introduce propper debugger state
	//breakpoints
	//stepthrough
	//backtrack
	//inspect memory address
//TODO visual code show in debug view
