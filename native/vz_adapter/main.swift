// Q1-C1: pure contract only. No Virtualization import, native handle, socket or VM entrypoint.
// C2/C3 must separately establish original-Owner custody and approved native artifacts.
import CryptoKit
import Foundation

enum ContractError: String, Error {
    case invalidFrame = "INVALID_FRAME"
    case identityMismatch = "IDENTITY_MISMATCH"
    case staleEpoch = "STALE_EPOCH"
    case invalidDescriptor = "INVALID_DESCRIPTOR"
    case invalidTransition = "INVALID_TRANSITION"
    case replay = "REPLAY_DETECTED"
    case capacity = "CAPACITY_EXCEEDED"
    case channelDenied = "CHANNEL_DENIED"
    case revoked = "CAPABILITY_REVOKED"
    case nativeNotAuthorized = "NATIVE_NOT_AUTHORIZED"
    case stopUncertain = "STOP_UNCERTAIN"
}

indirect enum JSONValue: Equatable {
    case object([String: JSONValue]), array([JSONValue]), string(String), integer(Int64), bool(Bool), null

    static func == (lhs: JSONValue, rhs: JSONValue) -> Bool {
        switch (lhs, rhs) {
        case let (.string(a), .string(b)): return a.utf8.elementsEqual(b.utf8)
        case let (.integer(a), .integer(b)): return a == b
        case let (.bool(a), .bool(b)): return a == b
        case let (.array(a), .array(b)): return a == b
        case let (.object(a), .object(b)): return a == b
        case (.null, .null): return true
        default: return false
        }
    }
    func object(keys: Set<String>) throws -> [String: JSONValue] {
        guard case let .object(value) = self, Set(value.keys) == keys else {
            throw ContractError.invalidFrame
        }
        return value
    }
    func string() throws -> String {
        guard case let .string(value) = self else { throw ContractError.invalidFrame }
        return value
    }
    func integer() throws -> Int64 {
        guard case let .integer(value) = self else { throw ContractError.invalidFrame }
        return value
    }
    var foundation: Any {
        switch self {
        case let .object(value): return value.mapValues { $0.foundation }
        case let .array(value): return value.map { $0.foundation }
        case let .string(value): return value
        case let .integer(value): return value
        case let .bool(value): return value
        case .null: return NSNull()
        }
    }
}

// Parse containers/numbers ourselves: Foundation's dictionaries erase duplicate keys,
// and NSNumber erases the bool/integer distinction. Foundation only decodes string escapes.
struct StrictJSON {
    static let frameLimit = 65_536
    private let bytes: [UInt8]
    private var index = 0

    init(_ data: Data, limit: Int = frameLimit) throws {
        guard !data.isEmpty, data.count <= limit, String(data: data, encoding: .utf8) != nil else {
            throw ContractError.invalidFrame
        }
        bytes = Array(data)
    }
    mutating func decode() throws -> JSONValue {
        let result = try value(depth: 0)
        whitespace()
        guard index == bytes.count else { throw ContractError.invalidFrame }
        return result
    }
    private mutating func whitespace() {
        while index < bytes.count, [9, 10, 13, 32].contains(bytes[index]) { index += 1 }
    }
    private mutating func consume(_ byte: UInt8) -> Bool {
        whitespace()
        guard index < bytes.count, bytes[index] == byte else { return false }
        index += 1
        return true
    }
    private mutating func value(depth: Int) throws -> JSONValue {
        whitespace()
        guard depth <= 8, index < bytes.count else { throw ContractError.invalidFrame }
        switch bytes[index] {
        case 123:
            guard depth < 8 else { throw ContractError.invalidFrame }
            return try object(depth: depth)
        case 91:
            guard depth < 8 else { throw ContractError.invalidFrame }
            return try array(depth: depth)
        case 34: return .string(try string())
        case 116: return try literal("true", .bool(true))
        case 102: return try literal("false", .bool(false))
        case 110: return try literal("null", .null)
        default: return try number()
        }
    }
    private mutating func object(depth: Int) throws -> JSONValue {
        index += 1
        var result: [String: JSONValue] = [:]
        if consume(125) { return .object(result) }
        repeat {
            whitespace()
            let key = try string()
            // All protocol fields are ASCII. Reject Unicode aliases before Swift's
            // canonically equivalent String dictionary/Set equality can erase them.
            guard key.utf8.allSatisfy({ $0 < 128 }) else { throw ContractError.invalidFrame }
            guard result[key] == nil, consume(58) else { throw ContractError.invalidFrame }
            result[key] = try value(depth: depth + 1)
            if consume(125) { return .object(result) }
        } while consume(44)
        throw ContractError.invalidFrame
    }
    private mutating func array(depth: Int) throws -> JSONValue {
        index += 1
        var result: [JSONValue] = []
        if consume(93) { return .array(result) }
        repeat {
            result.append(try value(depth: depth + 1))
            if consume(93) { return .array(result) }
        } while consume(44)
        throw ContractError.invalidFrame
    }
    private mutating func string() throws -> String {
        guard index < bytes.count, bytes[index] == 34 else { throw ContractError.invalidFrame }
        let start = index
        index += 1
        while index < bytes.count {
            let byte = bytes[index]
            index += 1
            if byte == 34 {
                let data = Data(bytes[start..<index])
                guard let result = try? JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed),
                      let text = result as? String else { throw ContractError.invalidFrame }
                return text
            }
            guard byte >= 32 else { throw ContractError.invalidFrame }
            if byte == 92 {
                guard index < bytes.count else { throw ContractError.invalidFrame }
                index += 1
            }
        }
        throw ContractError.invalidFrame
    }
    private mutating func literal(_ text: String, _ result: JSONValue) throws -> JSONValue {
        let expected = Array(text.utf8)
        guard index + expected.count <= bytes.count,
              Array(bytes[index..<(index + expected.count)]) == expected else { throw ContractError.invalidFrame }
        index += expected.count
        return result
    }
    private mutating func number() throws -> JSONValue {
        let start = index
        if index < bytes.count, bytes[index] == 45 { index += 1 }
        guard index < bytes.count, (48...57).contains(bytes[index]) else { throw ContractError.invalidFrame }
        if bytes[index] == 48 { index += 1 } else {
            while index < bytes.count, (48...57).contains(bytes[index]) { index += 1 }
        }
        let text = String(decoding: bytes[start..<index], as: UTF8.self)
        guard let result = Int64(text) else { throw ContractError.invalidFrame }
        return .integer(result)
    }
}

func decodeJSON(_ data: Data, limit: Int = StrictJSON.frameLimit) throws -> JSONValue {
    var parser = try StrictJSON(data, limit: limit)
    return try parser.decode()
}

func digest(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func isToken(_ text: String) -> Bool {
    !text.isEmpty && text.utf8.count <= 128 && text.utf8.allSatisfy {
        (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45, 46, 58, 95].contains($0)
    }
}
func isDigest(_ text: String) -> Bool {
    text.utf8.count == 64 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
func isPinnedPath(_ text: String) -> Bool {
    let parts = text.split(separator: "/", omittingEmptySubsequences: false)
    return text.hasPrefix("/") && text.utf8.count <= 1024 && parts.count > 1 &&
        parts.dropFirst().allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." } &&
        !text.unicodeScalars.contains { $0.value < 32 || $0.value == 127 }
}

struct Binding: Equatable {
    static let names: Set<String> = ["VM_ID", "TASK_ID", "RUN_ID", "OWNER_EPOCH", "BOOT_ID", "ADAPTER_PID",
        "ADAPTER_BIRTH", "VZ_INSTANCE_ID", "IMAGE_DIGEST", "POLICY_DIGEST", "SOCKET_ENDPOINT", "CONNECTION_GENERATION"]
    let fields: [String: JSONValue]
    init(_ value: JSONValue) throws {
        fields = try value.object(keys: Self.names)
        for (key, value) in fields {
            if ["OWNER_EPOCH", "ADAPTER_PID", "CONNECTION_GENERATION"].contains(key) {
                guard try value.integer() > 0 else { throw ContractError.invalidFrame }
            } else {
                let text = try value.string()
                guard ["IMAGE_DIGEST", "POLICY_DIGEST"].contains(key) ? isDigest(text) : isToken(text) else {
                    throw ContractError.invalidFrame
                }
            }
        }
    }
    func check(_ other: Binding) throws {
        guard fields["OWNER_EPOCH"] == other.fields["OWNER_EPOCH"] else { throw ContractError.staleEpoch }
        guard self == other else { throw ContractError.identityMismatch }
    }
}

struct Channel: Equatable {
    let name: String
    let port: Int64
    let direction: String
    let capability: String
    static let all = [
        Channel(name: "owner_control", port: 4000, direction: "OWNER_TO_GUEST", capability: "INERT_DIAGNOSTIC_ONLY"),
        Channel(name: "worker_rpc", port: 4001, direction: "GUEST_TO_HOST", capability: "DISABLED"),
        Channel(name: "inference", port: 4002, direction: "GUEST_TO_HOST", capability: "DISABLED"),
        Channel(name: "lifecycle", port: 4003, direction: "GUEST_TO_HOST", capability: "UNTRUSTED_DIAGNOSTIC_ONLY"),
        Channel(name: "stop_revoke", port: 4004, direction: "OWNER_TO_GUEST", capability: "STOP_NOTICE_ONLY")
    ]
    var json: JSONValue {
        .object(["name": .string(name), "port": .integer(port), "direction": .string(direction),
                 "capability": .string(capability)])
    }
}

struct Descriptor {
    static let version = "Q1C_ADAPTER_V1"
    let binding: Binding
    let taskDirectory: JSONValue
    let inventory: JSONValue
    let manifestDigest: String

    // Structural pins are NOT approval, path ownership, Host containment or a native grant.
    init(_ data: Data) throws {
        do { try self.init(value: decodeJSON(data)) }
        catch let error as ContractError where error == .invalidFrame { throw ContractError.invalidDescriptor }
    }
    private init(value: JSONValue) throws {
        let object = try value.object(keys: ["version", "binding", "artifacts", "resources", "task_directory", "devices"])
        guard object["version"] == .string(Self.version) else { throw ContractError.invalidDescriptor }
        binding = try Binding(object["binding"]!)
        let artifacts = try object["artifacts"]!.object(keys: ["kernel", "initramfs", "disk", "policy"])
        for artifact in artifacts.values {
            let pin = try artifact.object(keys: ["path", "sha256"])
            guard try isPinnedPath(pin["path"]!.string()), try isDigest(pin["sha256"]!.string()) else {
                throw ContractError.invalidDescriptor
            }
        }
        let disk = try artifacts["disk"]!.object(keys: ["path", "sha256"])
        let policy = try artifacts["policy"]!.object(keys: ["path", "sha256"])
        guard disk["sha256"] == binding.fields["IMAGE_DIGEST"],
              policy["sha256"] == binding.fields["POLICY_DIGEST"] else { throw ContractError.invalidDescriptor }
        let paths = try artifacts.values.map { try $0.object(keys: ["path", "sha256"])["path"]!.string() }
        guard Set(paths).count == paths.count else { throw ContractError.invalidDescriptor }
        let resources = try object["resources"]!.object(keys: ["vcpus", "memory_bytes", "disk_bytes", "startup_seconds", "stop_seconds", "total_seconds"])
        let bounds: [String: Int64] = ["vcpus": 2, "memory_bytes": 2_147_483_648, "disk_bytes": 8_589_934_592,
                                     "startup_seconds": 60, "stop_seconds": 30, "total_seconds": 300]
        for (key, bound) in bounds {
            let number = try resources[key]!.integer()
            guard number > 0, number <= bound else { throw ContractError.invalidDescriptor }
        }
        guard try resources["startup_seconds"]!.integer() + resources["stop_seconds"]!.integer() <=
                    resources["total_seconds"]!.integer() else { throw ContractError.invalidDescriptor }
        taskDirectory = object["task_directory"]!
        let share = try taskDirectory.object(keys: ["path", "tag", "read_only"])
        guard try isPinnedPath(share["path"]!.string()), try isToken(share["tag"]!.string()),
              case .bool = share["read_only"]! else { throw ContractError.invalidDescriptor }
        guard !paths.contains(try share["path"]!.string()) else { throw ContractError.invalidDescriptor }
        inventory = .object([
            "network_devices": .array([]), "socket_devices": .integer(1),
            "task_share": taskDirectory, "storage": .array([artifacts["disk"]!]),
            "boot": .string("DIRECT_LINUX"), "console_devices": .integer(1), "entropy_devices": .integer(1),
            "channels": .array(Channel.all.map { $0.json })
        ])
        let devices = try object["devices"]!.object(keys: ["network_devices", "socket_devices", "console_devices", "entropy_devices"])
        guard devices["network_devices"] == .array([]), devices["socket_devices"] == .integer(1),
              devices["console_devices"] == .integer(1), devices["entropy_devices"] == .integer(1) else {
            throw ContractError.invalidDescriptor
        }
        manifestDigest = try digest(JSONSerialization.data(withJSONObject: inventory.foundation, options: [.sortedKeys]))
    }
}

enum AdapterState: String {
    case new = "NEW", configured = "CONFIGURED", validated = "VALIDATED", starting = "STARTING", running = "RUNNING"
    case revoking = "REVOKING", stoppedObserved = "STOPPED_OBSERVED", stopUncertain = "STOP_UNCERTAIN"
}

enum Observation {
    case configured, validated, starting, running, revoke, stopped, uncertainty
}

// Pure transition specification; not evidence that any native operation occurred.
// Stop uncertainty is sticky. STOP_VERIFIED is deliberately not an Adapter state.
struct Lifecycle {
    private(set) var state: AdapterState = .new
    private(set) var capabilitiesRevoked = false
    mutating func invalidate() {
        capabilitiesRevoked = true
        state = .stopUncertain
    }
    mutating func observe(_ event: Observation) throws {
        if event == .uncertainty { invalidate(); return }
        if event == .revoke {
            capabilitiesRevoked = true
            if state != .stopUncertain && state != .stoppedObserved { state = .revoking }
            return
        }
        let next: AdapterState
        switch (state, event) {
        case (.new, .configured): next = .configured
        case (.configured, .validated): next = .validated
        case (.validated, .starting): next = .starting
        case (.starting, .running): next = .running
        case (.revoking, .stopped): next = .stoppedObserved
        default: throw ContractError.invalidTransition
        }
        state = next
    }
}

struct Frame {
    let requestID: String
    let sequence: Int64
    let operation: String
    let binding: Binding
    let payload: JSONValue
    let fingerprint: String
    init(_ data: Data) throws {
        let value = try decodeJSON(data).object(keys: ["version", "request_id", "sequence", "operation", "binding", "payload"])
        guard value["version"] == .string(Descriptor.version) else { throw ContractError.invalidFrame }
        requestID = try value["request_id"]!.string()
        sequence = try value["sequence"]!.integer()
        operation = try value["operation"]!.string()
        guard isToken(requestID), sequence > 0, isToken(operation) else { throw ContractError.invalidFrame }
        binding = try Binding(value["binding"]!)
        payload = value["payload"]!
        guard case .object = payload else { throw ContractError.invalidFrame }
        fingerprint = digest(data)
    }
}

struct Receipt: Equatable {
    let code: String
    let reference: String
    let state: AdapterState
    let plannedInventory: JSONValue?
    var json: JSONValue {
        .object(["code": .string(code), "observation_ref": .string(reference), "state": .string(state.rawValue),
                 "inventory_kind": .string("PLANNED_ONLY"), "inventory": plannedInventory ?? .null,
                 "native_observation": .string("NOT_RUN"), "stop_verified": .bool(false)])
    }
}

struct AdapterContract {
    static let nativeOperations: Set<String> = ["create_vm", "validate_configuration", "start_vm", "accept_scoped_socket", "stop_exact_vm"]
    let descriptor: Descriptor
    private(set) var lifecycle = Lifecycle()
    private var sequence: Int64 = 0
    private var receipts: [String: (Frame, Receipt)] = [:]
    // Ordinary capacity must never consume terminal safety/readback capacity.
    // Keep one revoke receipt and one immutable readback per finite lifecycle state.
    // Additional fresh IDs for an already recorded terminal state fail capacity;
    // exact duplicates remain replayable. This is a finite offline contract, not a queue.
    private var terminalReceipts: [String: (Frame, Receipt)] = [:]

    mutating func transportLost() {
        // No native custody witness is available; EOF/error/timeout never clears uncertainty.
        lifecycle.invalidate()
    }
    mutating func handle(_ data: Data) throws -> Receipt {
        let frame = try Frame(data)
        try descriptor.binding.check(frame.binding)
        try validatePayload(frame)
        let terminal = terminalReceipts.values.first { $0.0.requestID == frame.requestID }
        if let (old, receipt) = receipts[frame.requestID] ?? terminal {
            guard old.sequence == frame.sequence, old.fingerprint == frame.fingerprint else { throw ContractError.replay }
            guard !lifecycle.capabilitiesRevoked || ["revoke", "lifecycle_receipt"].contains(frame.operation) else {
                throw ContractError.revoked
            }
            return receipt
        }
        guard frame.sequence == sequence + 1 else { throw ContractError.replay }
        let terminalKey: String?
        switch frame.operation {
        case "revoke": terminalKey = "revoke"
        case "lifecycle_receipt": terminalKey = "lifecycle_receipt:\(lifecycle.state.rawValue)"
        default: terminalKey = nil
        }
        if let key = terminalKey {
            guard terminalReceipts[key] == nil else { throw ContractError.capacity }
        } else {
            guard receipts.count < 16 else { throw ContractError.capacity }
        }
        let result = try execute(frame)
        sequence = frame.sequence
        let receipt = Receipt(code: result, reference: "q1c-pure:\(frame.sequence):\(frame.fingerprint)",
                              state: lifecycle.state, plannedInventory: frame.operation == "enumerate_devices" ? descriptor.inventory : nil)
        if let key = terminalKey { terminalReceipts[key] = (frame, receipt) }
        else { receipts[frame.requestID] = (frame, receipt) }
        return receipt
    }
    private func validatePayload(_ frame: Frame) throws {
        switch frame.operation {
        case "attach_task_directory":
            guard frame.payload == descriptor.taskDirectory else { throw ContractError.invalidDescriptor }
        case "accept_scoped_socket":
            let payload = try frame.payload.object(keys: ["channel", "port", "direction", "capability"])
            let channel = try payload["channel"]!.string()
            guard let allowed = Channel.all.first(where: { $0.name == channel }), allowed.capability != "DISABLED",
                  payload["port"] == .integer(allowed.port), payload["direction"] == .string(allowed.direction),
                  payload["capability"] == .string(allowed.capability) else { throw ContractError.channelDenied }
        case "contract_check", "enumerate_devices", "create_vm", "validate_configuration", "start_vm", "revoke", "stop_exact_vm", "lifecycle_receipt":
            _ = try frame.payload.object(keys: [])
        default: throw ContractError.invalidFrame
        }
    }
    private mutating func execute(_ frame: Frame) throws -> String {
        // No descriptor, caller-supplied grant or simulated observation can open this gate.
        if Self.nativeOperations.contains(frame.operation) { return ContractError.nativeNotAuthorized.rawValue }
        if frame.operation == "revoke" { try lifecycle.observe(.revoke); return "CAPABILITIES_REVOKED" }
        if frame.operation == "lifecycle_receipt" {
            return lifecycle.state == .stopUncertain ? ContractError.stopUncertain.rawValue : "NATIVE_NOT_OBSERVED"
        }
        guard !lifecycle.capabilitiesRevoked else { throw ContractError.revoked }
        if frame.operation == "attach_task_directory", lifecycle.state != .new { throw ContractError.invalidTransition }
        return frame.operation == "enumerate_devices" ? "PLANNED_ONLY" : "SHAPE_VALID_AUTHORITY_NOT_VERIFIED"
    }
}

#if Q1C_CONTRACT_CLI
// Test-only finite contract_check. Input contains raw descriptor/frame strings so
// duplicate keys, UTF-8, depth and byte bounds are tested by the actual wire parser.
// Not an Owner endpoint, not a native daemon; never reads paths named in descriptors.
@main enum ContractCheck {
    static func main() {
        do {
            let limit = 2_200_000
            var input = Data()
            while let part = try FileHandle.standardInput.read(upToCount: min(65_536, limit + 1 - input.count)), !part.isEmpty {
                input.append(part)
                guard input.count <= limit else { throw ContractError.invalidFrame }
            }
            let value = try decodeJSON(input, limit: limit).object(keys: ["descriptor", "frames", "transport_end"])
            let descriptor = try Descriptor(Data(value["descriptor"]!.string().utf8))
            guard case let .array(frames) = value["frames"], frames.count <= 16 else { throw ContractError.capacity }
            guard let end = value["transport_end"], [.null, .string("EOF"), .string("ERROR"), .string("TIMEOUT")].contains(end) else {
                throw ContractError.invalidFrame
            }
            var adapter = AdapterContract(descriptor: descriptor)
            var results: [JSONValue] = []
            for raw in frames {
                do { results.append(try adapter.handle(Data(raw.string().utf8)).json) }
                catch let error as ContractError { results.append(.object(["code": .string(error.rawValue)])) }
            }
            if end != .null { adapter.transportLost() }
            try output(.object(["results": .array(results), "state": .string(adapter.lifecycle.state.rawValue),
                                "capabilities_revoked": .bool(adapter.lifecycle.capabilitiesRevoked),
                                "manifest_sha256": .string(descriptor.manifestDigest), "inventory": descriptor.inventory,
                                "authority": .string("NOT_VERIFIED"), "native": .string("NOT_RUN")]))
        } catch let error as ContractError { try? output(.object(["error": .string(error.rawValue)])) }
        catch { try? output(.object(["error": .string(ContractError.invalidFrame.rawValue)])) }
    }
    static func output(_ value: JSONValue) throws {
        let bytes = try JSONSerialization.data(withJSONObject: value.foundation, options: [.sortedKeys])
        FileHandle.standardOutput.write(bytes + Data([10]))
    }
}
#endif
