//! Incomplete TLS listener for the copied-certificate case.
//!
//! The process accepts a public certificate and one or more ports. It reads a
//! ClientHello and answers with a fatal handshake alert. It has no signing
//! key, so the handshake cannot finish.
const std = @import("std");

pub const alert_record = [_]u8{ 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };

pub const ArgsError = error{
    PrivateKeyArgument,
    MissingCertificate,
    MissingPort,
    InvalidPort,
    InvalidBind,
};

pub const CertError = error{
    NotACertificate,
    PrivateKeyMaterial,
};

pub const Options = struct {
    cert_path: []const u8,
    bind_host: []const u8 = "0.0.0.0",
    ports: [8]u16 = std.mem.zeroes([8]u16),
    port_count: usize = 0,
};

pub fn rejectPrivateFlag(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--key") or
        std.mem.eql(u8, arg, "--private-key") or
        std.mem.eql(u8, arg, "-key") or
        std.mem.endsWith(u8, arg, ".key");
}

pub fn validateCertificate(pem: []const u8) CertError!void {
    if (std.mem.indexOf(u8, pem, "PRIVATE KEY") != null) return error.PrivateKeyMaterial;
    if (std.mem.indexOf(u8, pem, "BEGIN CERTIFICATE") == null) return error.NotACertificate;
}

pub fn parseArgs(items: []const []const u8) ArgsError!Options {
    var cert: ?[]const u8 = null;
    var bind_host: []const u8 = "0.0.0.0";
    var ports_buf: [8]u16 = undefined;
    var port_count: usize = 0;
    var i: usize = 0;
    while (i < items.len) : (i += 1) {
        const arg = items[i];
        if (rejectPrivateFlag(arg)) return error.PrivateKeyArgument;
        if (std.mem.eql(u8, arg, "--cert")) {
            i += 1;
            if (i >= items.len) return error.MissingCertificate;
            cert = items[i];
        } else if (std.mem.eql(u8, arg, "--bind")) {
            i += 1;
            if (i >= items.len) return error.InvalidBind;
            bind_host = items[i];
        } else if (std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i >= items.len) return error.MissingPort;
            const port = std.fmt.parseInt(u16, items[i], 10) catch return error.InvalidPort;
            if (port == 0 or port_count == ports_buf.len) return error.InvalidPort;
            ports_buf[port_count] = port;
            port_count += 1;
        } else {
            return error.InvalidBind;
        }
    }
    if (cert == null) return error.MissingCertificate;
    if (port_count == 0) return error.MissingPort;
    var options = Options{
        .cert_path = cert.?,
        .bind_host = bind_host,
        .port_count = port_count,
    };
    @memcpy(options.ports[0..port_count], ports_buf[0..port_count]);
    return options;
}

fn handle(io: std.Io, stream: std.Io.net.Stream) void {
    var buffer: [2048]u8 = undefined;
    var chunk = [_][]u8{buffer[0..]};
    _ = stream.read(io, &chunk) catch {};
    var out_buf: [32]u8 = undefined;
    var writer = stream.writer(io, &out_buf);
    writer.interface.writeAll(&alert_record) catch {};
    writer.interface.flush() catch {};
    stream.close(io);
}

fn serve(io: std.Io, host: []const u8, port: u16) !void {
    var address = try std.Io.net.IpAddress.parse(host, port);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    while (true) {
        const stream = server.accept(io) catch continue;
        handle(io, stream);
    }
}

pub fn main(init: std.process.Init) !void {
    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer iterator.deinit();
    _ = iterator.next();
    var collected: [16][]const u8 = undefined;
    var count: usize = 0;
    while (iterator.next()) |arg| {
        if (count == collected.len) std.process.exit(2);
        collected[count] = arg;
        count += 1;
    }
    const options = parseArgs(collected[0..count]) catch std.process.exit(2);
    const pem = std.Io.Dir.cwd().readFileAlloc(
        init.io,
        options.cert_path,
        init.gpa,
        .limited(1024 * 1024),
    ) catch std.process.exit(3);
    defer init.gpa.free(pem);
    validateCertificate(pem) catch std.process.exit(3);
    const ports = options.ports[0..options.port_count];
    if (ports.len == 1) {
        try serve(init.io, options.bind_host, ports[0]);
        return;
    }
    var threads: [8]std.Thread = undefined;
    for (ports, 0..) |port, index| {
        threads[index] = try std.Thread.spawn(.{}, serveThread, .{ init.io, options.bind_host, port });
    }
    for (ports, 0..) |_, index| threads[index].join();
}

fn serveThread(io: std.Io, host: []const u8, port: u16) void {
    serve(io, host, port) catch std.process.exit(4);
}

test "rejects a private key argument" {
    const items = [_][]const u8{ "--cert", "leaf.pem", "--key", "leaf.key", "--port", "15911" };
    try std.testing.expectError(error.PrivateKeyArgument, parseArgs(&items));
}

test "rejects a private key file" {
    try std.testing.expectError(error.PrivateKeyMaterial, validateCertificate(
        "-----BEGIN PRIVATE KEY-----\nMQ==\n-----END PRIVATE KEY-----\n",
    ));
    try std.testing.expectError(error.NotACertificate, validateCertificate("not a certificate"));
}

test "accepts a certificate and ports" {
    const items = [_][]const u8{ "--cert", "leaf.pem", "--port", "15911", "--port", "15912" };
    const options = try parseArgs(&items);
    try std.testing.expectEqual(@as(usize, 2), options.port_count);
    try validateCertificate("-----BEGIN CERTIFICATE-----\nMQ==\n-----END CERTIFICATE-----\n");
}

test "alert is not a completed handshake" {
    try std.testing.expectEqual(@as(u8, 0x15), alert_record[0]);
    try std.testing.expect(std.mem.indexOfScalar(u8, &alert_record, 0x14) == null);
    try std.testing.expectEqual(@as(u8, 2), alert_record[5]);
    try std.testing.expectEqual(@as(u8, 40), alert_record[6]);

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const port: u16 = 45911;
    var address = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var server = try address.listen(io, .{ .reuse_address = true });
    const client_thread = try std.Thread.spawn(.{}, clientOnce, .{ io, port });
    const stream = try server.accept(io);
    handle(io, stream);
    client_thread.join();
    server.deinit(io);
}

fn clientOnce(io: std.Io, port: u16) void {
    var address = std.Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
    const stream = address.connect(io, .{ .mode = .stream }) catch unreachable;
    defer stream.close(io);
    var hello = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00 };
    var out_buf: [32]u8 = undefined;
    var writer = stream.writer(io, &out_buf);
    writer.interface.writeAll(&hello) catch unreachable;
    writer.interface.flush() catch unreachable;
    var buffer: [32]u8 = undefined;
    var chunk = [_][]u8{buffer[0..]};
    const n = stream.read(io, &chunk) catch unreachable;
    std.testing.expect(n >= 7) catch unreachable;
    std.testing.expectEqual(@as(u8, 0x15), buffer[0]) catch unreachable;
}
