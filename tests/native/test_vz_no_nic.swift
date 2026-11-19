// Compile with main.swift and -parse-as-library; no VZ import/API, signing or entitlement use.
import Foundation

struct TestFailure: Error { let message: String }
struct Suite {
    var assertions = 0
    mutating func check(_ condition: Bool, _ message: String) throws {
        assertions += 1
        if !condition { throw TestFailure(message: message) }
    }
    mutating func rejects(_ error: ContractError, _ body: () throws -> Void) throws {
        do { try body() } catch let actual as ContractError {
            try check(actual == error, "expected \(error), got \(actual)")
            return
        }
        throw TestFailure(message: "expected rejection: \(error)")
    }
}

func fixture() -> JSONValue {
    let binding: [String: JSONValue] = [
        "VM_ID": .string("test:vm"), "TASK_ID": .string("test:task"), "RUN_ID": .string("test:run"),
        "OWNER_EPOCH": .integer(1), "BOOT_ID": .string("test:boot"), "ADAPTER_PID": .integer(123),
        "ADAPTER_BIRTH": .string("test:birth"), "VZ_INSTANCE_ID": .string("test:instance"),
        "IMAGE_DIGEST": .string(String(repeating: "a", count: 64)), "POLICY_DIGEST": .string(String(repeating: "b", count: 64)),
        "SOCKET_ENDPOINT": .string("test:pair"), "CONNECTION_GENERATION": .integer(1)
    ]
    func artifact(_ name: String, _ hash: String) -> JSONValue {
        .object(["path": .string("/fixture/\(name)"), "sha256": .string(String(repeating: hash, count: 64))])
    }
    return .object([
        "version": .string(Descriptor.version), "binding": .object(binding),
        "artifacts": .object(["kernel": artifact("kernel", "c"), "initramfs": artifact("initramfs", "d"),
                              "disk": artifact("disk", "a"), "policy": artifact("policy", "b")]),
        "resources": .object(["vcpus": .integer(2), "memory_bytes": .integer(2_147_483_648), "disk_bytes": .integer(8_589_934_592),
                              "startup_seconds": .integer(60), "stop_seconds": .integer(30), "total_seconds": .integer(300)]),
        "task_directory": .object(["path": .string("/fixture/task"), "tag": .string("task"), "read_only": .bool(true)]),
        "devices": .object(["network_devices": .array([]), "socket_devices": .integer(1), "console_devices": .integer(1), "entropy_devices": .integer(1)])
    ])
}
func encoded(_ value: JSONValue) throws -> Data {
    try JSONSerialization.data(withJSONObject: value.foundation, options: [.sortedKeys, .fragmentsAllowed])
}
func request(_ descriptor: Descriptor, _ operation: String, _ sequence: Int64, payload: JSONValue = .object([:])) throws -> Data {
    try encoded(.object(["version": .string(Descriptor.version), "request_id": .string("test:req:\(sequence)"),
                         "sequence": .integer(sequence), "operation": .string(operation),
                         "binding": .object(descriptor.binding.fields), "payload": payload]))
}

@main enum NoNICTests {
    static func main() throws {
        var suite = Suite()
        try descriptorTests(&suite)
        try parserTests(&suite)
        try lifecycleTests(&suite)
        try adapterTests(&suite)
        print("PASS \(suite.assertions) actual Swift assertions; pure contract only; VZ_API_OPERATIONS=NOT_RUN")
    }

    static func descriptorTests(_ suite: inout Suite) throws {
        let descriptor = try Descriptor(encoded(fixture()))
        let inv = try descriptor.inventory.object(keys: ["network_devices", "socket_devices", "task_share", "storage", "boot", "console_devices", "entropy_devices", "channels"])
        try suite.check(inv["network_devices"] == .array([]), "no NIC declaration")
        try suite.check(inv["socket_devices"] == .integer(1), "one vsock device")
        try suite.check(inv["task_share"] == descriptor.taskDirectory, "one exact pinned share")
        try suite.check(inv["channels"] == .array(Channel.all.map { $0.json }), "finite channels")
        try suite.check(inv["boot"] == .string("DIRECT_LINUX"), "no platform/boot fallback")
        try suite.check(descriptor.manifestDigest == digest(encoded(descriptor.inventory)), "manifest covers exact inventory")
        try suite.check(Channel.all.map { $0.port } == [4000, 4001, 4002, 4003, 4004], "fixed ports")
        try suite.check(Channel.all.filter { $0.capability == "DISABLED" }.map { $0.port } == [4001, 4002], "RPC/inference disabled")
        try suite.check(!isPinnedPath("/a/../b") && !isPinnedPath("/a//b") && !isPinnedPath("relative"), "lexical root checks")
        try suite.check(JSONValue.string("é") != .string("e\u{301}"), "no Unicode path normalization")
        try suite.rejects(.invalidDescriptor) { _ = try Descriptor(Data("{}".utf8)) }
        let raw = String(decoding: try encoded(fixture()), as: UTF8.self)
        try suite.rejects(.invalidDescriptor) { _ = try Descriptor(Data(raw.replacingOccurrences(of: "\"socket_devices\":1", with: "\"socket_devices\":2").utf8)) }
        try suite.rejects(.invalidDescriptor) { _ = try Descriptor(Data(raw.replacingOccurrences(of: "\"network_devices\":[]", with: "\"network_devices\":[\"NIC\"]").utf8)) }
    }

    static func parserTests(_ suite: inout Suite) throws {
        for raw in ["{\"a\":1,\"a\":2}", "{\"a\":1,\"\\u0061\":2}", "[1.0]", "[1e0]", "[NaN]", "[Infinity]",
                    "[01]", "[+1]", "[--1]", "[9223372036854775808]", "[-9223372036854775809]", "[true,]",
                    "{\"a\":\"\\ud800\"}", "{\"a\":\"\\udfff\"}", "{}x", "", "[" + String(repeating: "[", count: 9) + "0" + String(repeating: "]", count: 10)] {
            try suite.rejects(.invalidFrame) { _ = try decodeJSON(Data(raw.utf8)) }
        }
        try suite.rejects(.invalidFrame) { _ = try decodeJSON(Data([0xff])) }
        try suite.rejects(.invalidFrame) {
            _ = try decodeJSON(Data((String(repeating: "[", count: 9) + String(repeating: "]", count: 9)).utf8))
        }
        try suite.check(try decodeJSON(Data("[-9223372036854775808,9223372036854775807]".utf8)) ==
                        .array([.integer(Int64.min), .integer(Int64.max)]), "exact integer endpoints")
        try suite.check(try decodeJSON(Data("[\"\\ud800\\udc00\",true,false,null]".utf8)) ==
                        .array([.string("\u{10000}"), .bool(true), .bool(false), .null]), "valid scalars and literals")
        let exact = Data(("{}" + String(repeating: " ", count: 65_534)).utf8)
        try suite.check(try decodeJSON(exact) == .object([:]), "64KiB inclusive")
        try suite.rejects(.invalidFrame) { _ = try decodeJSON(exact + Data([32])) }
        try suite.check(try decodeJSON(Data((String(repeating: "[", count: 8) + "0" + String(repeating: "]", count: 8)).utf8)) != .null, "depth inclusive")
    }

    static func lifecycleTests(_ suite: inout Suite) throws {
        let path: [Observation] = [.configured, .validated, .starting, .running, .revoke, .stopped]
        let states: [AdapterState] = [.new, .configured, .validated, .starting, .running, .revoking, .stoppedObserved]
        // Every state/event pair is exercised, not only the happy path.
        let events: [Observation] = [.configured, .validated, .starting, .running, .revoke, .stopped, .uncertainty]
        for index in states.indices {
            var seed = Lifecycle()
            for event in path.prefix(index) { try seed.observe(event) }
            try suite.check(seed.state == states[index], "seed state")
            for event in events {
                var test = seed
                if event == .uncertainty {
                    try test.observe(event)
                    try suite.check(test.state == .stopUncertain && test.capabilitiesRevoked, "uncertainty sticky")
                } else if event == .revoke {
                    try test.observe(event)
                    let expected: AdapterState = states[index] == .stoppedObserved ? .stoppedObserved : .revoking
                    try suite.check(test.state == expected && test.capabilitiesRevoked, "idempotent revoke")
                } else if index < path.count && event == path[index] {
                    try test.observe(event)
                    try suite.check(test.state == states[index + 1], "legal observed transition")
                } else {
                    try suite.rejects(.invalidTransition) { try test.observe(event) }
                    try suite.check(test.state == seed.state, "failed transition immutable")
                }
            }
        }
        var unknown = Lifecycle()
        try unknown.observe(.uncertainty)
        try unknown.observe(.revoke)
        for event in events where event != .revoke && event != .uncertainty {
            try suite.rejects(.invalidTransition) { try unknown.observe(event) }
            try suite.check(unknown.state == .stopUncertain, "late event cannot clear uncertainty")
        }
    }

    static func adapterTests(_ suite: inout Suite) throws {
        let desc = try Descriptor(encoded(fixture()))
        var adapter = AdapterContract(descriptor: desc)
        let operations = AdapterContract.nativeOperations.subtracting(["accept_scoped_socket"]).sorted()
        for (index, operation) in operations.enumerated() {
            let receipt = try adapter.handle(request(desc, operation, Int64(index + 1)))
            try suite.check(receipt.code == "NATIVE_NOT_AUTHORIZED" && receipt.state == .new, "native operation gated")
        }
        var capacity = AdapterContract(descriptor: desc)
        for sequence in 1...16 {
            _ = try capacity.handle(request(desc, "contract_check", Int64(sequence)))
        }
        try suite.rejects(.capacity) { _ = try capacity.handle(request(desc, "contract_check", 17)) }
        let cached = try capacity.handle(request(desc, "contract_check", 16))
        try suite.check(cached.reference.hasPrefix("q1c-pure:16:"), "cache survives full bound")
        let revoke = try request(desc, "revoke", 17)
        let revoked = try capacity.handle(revoke)
        try suite.check(capacity.lifecycle.capabilitiesRevoked && revoked.state == .revoking, "full capacity cannot block revoke")
        try suite.check(try capacity.handle(revoke) == revoked, "full-capacity revoke exact replay")
        let beforeLoss = try capacity.handle(request(desc, "lifecycle_receipt", 18))
        try suite.check(beforeLoss.code == "NATIVE_NOT_OBSERVED", "full-capacity lifecycle readback")
        capacity.transportLost()
        let readback = try request(desc, "lifecycle_receipt", 19)
        let afterLoss = try capacity.handle(readback)
        try suite.check(afterLoss.code == "STOP_UNCERTAIN" && afterLoss.state == .stopUncertain, "uncertainty readback after capacity and earlier receipt")
        try suite.check(try capacity.handle(readback) == afterLoss, "uncertainty receipt idempotence")
        try suite.check(try capacity.handle(revoke) == revoked, "old revoke observation remains immutable")
        try suite.rejects(.capacity) {
            _ = try capacity.handle(request(desc, "lifecycle_receipt", 20, payload: .object([:])))
        }
        let changedID = String(decoding: try request(desc, "lifecycle_receipt", 20), as: UTF8.self)
            .replacingOccurrences(of: "test:req:20", with: "test:req:17")
        try suite.rejects(.replay) { _ = try capacity.handle(Data(changedID.utf8)) }
        var replay = AdapterContract(descriptor: desc)
        let raw = try request(desc, "enumerate_devices", 1)
        let first = try replay.handle(raw)
        try suite.check(first == replay.handle(raw), "exact duplicate same observation")
        try suite.rejects(.replay) { _ = try replay.handle(raw + Data([32])) }
        _ = try replay.handle(request(desc, "revoke", 2))
        try suite.rejects(.revoked) { _ = try replay.handle(raw) }
        replay.transportLost()
        replay.transportLost()
        let unknown = try replay.handle(request(desc, "lifecycle_receipt", 3))
        try suite.check(unknown.code == "STOP_UNCERTAIN" && unknown.state == .stopUncertain, "transport fault never verifies stop")
        for channel in Channel.all {
            var connection = AdapterContract(descriptor: desc)
            let payload: JSONValue = .object(["channel": .string(channel.name), "port": .integer(channel.port),
                                              "direction": .string(channel.direction), "capability": .string(channel.capability)])
            let data = try request(desc, "accept_scoped_socket", 1, payload: payload)
            if channel.capability == "DISABLED" {
                try suite.rejects(.channelDenied) { _ = try connection.handle(data) }
            } else {
                try suite.check(try connection.handle(data).code == "NATIVE_NOT_AUTHORIZED", "even allowed channel never opens socket")
            }
        }
    }
}
