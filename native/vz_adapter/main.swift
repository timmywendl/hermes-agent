// Q1 candidate: the pure contract never constructs VZ objects. The separately compiled
// Owner adapter denies native admission until protected containment/observer/approval
// evidence exists. A caller-controlled JSON grant cannot open that boundary.
import CryptoKit
import Foundation
#if Q1C_NATIVE_IMPLEMENTATION || Q1C_OWNER_ADAPTER
import Darwin
import Virtualization
#endif

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
    case containmentUnverified = "CONTAINMENT_UNVERIFIED"
    case artifactUnapproved = "ARTIFACT_UNAPPROVED"
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
    let artifacts: [String: JSONValue]
    let resources: [String: JSONValue]

    // Structural pins are NOT approval, path ownership, Host containment or a native grant.
    init(_ data: Data) throws {
        do { try self.init(value: decodeJSON(data)) }
        catch let error as ContractError where error == .invalidFrame { throw ContractError.invalidDescriptor }
    }
    private init(value: JSONValue) throws {
        let object = try value.object(keys: ["version", "binding", "artifacts", "resources", "task_directory", "devices"])
        guard object["version"] == .string(Self.version) else { throw ContractError.invalidDescriptor }
        binding = try Binding(object["binding"]!)
        artifacts = try object["artifacts"]!.object(keys: ["kernel", "initramfs", "disk", "policy"])
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
        resources = try object["resources"]!.object(keys: ["vcpus", "memory_bytes", "disk_bytes", "startup_seconds", "stop_seconds", "total_seconds"])
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
              share["read_only"] == .bool(true), share["tag"] == .string("task") else {
            throw ContractError.invalidDescriptor
        }
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

// Readiness is deliberately not a descriptor flag. The package currently has no
// supported protected-publication verifier or independent per-VM resource observer.
// Preserve this fact in one executable gate, before paths are opened or VZ is touched.
struct NativeReadiness {
    static let missing = ["HOST_POLICY_DENIAL_WITNESS", "INDEPENDENT_PER_VM_OBSERVER", "PROTECTED_HASH_BOUND_APPROVAL"]
    static var denial: JSONValue {
        .object(["code": .string(ContractError.containmentUnverified.rawValue),
                 "native": .string("NOT_RUN"), "stop_verified": .bool(false),
                 "missing": .array(missing.map { .string($0) })])
    }
}

// The stop request survives a start callback arriving after cancellation/deadline.
// Spend the one native stop attempt only when the exact retained VM can accept it.
// A stopped observation permits local handle closure, never physical retirement.
struct ExactStopActions: Equatable {
    let armDeadline: Bool
    let stopExact: Bool
    let closeObservedHandles: Bool
}
struct ExactStopPlan {
    private(set) var requested = false
    private(set) var attemptSpent = false
    private var deadlineArmed = false
    mutating func request(bootSpent: Bool, startPending: Bool, observedStopped: Bool, canStop: Bool) -> ExactStopActions {
        guard bootSpent else { return ExactStopActions(armDeadline: false, stopExact: false, closeObservedHandles: false) }
        requested = true
        let arm = !deadlineArmed
        deadlineArmed = true
        let close = observedStopped && !startPending
        let attempt = !observedStopped && canStop && !attemptSpent
        if attempt { attemptSpent = true }
        return ExactStopActions(armDeadline: arm, stopExact: attempt, closeObservedHandles: close)
    }
}
enum NativeDeadlines {
    static let totalSeconds: TimeInterval = 300
    static let stopSeconds: TimeInterval = 30
    static let startupSeconds: TimeInterval = 60
    static let stopReserveAt = totalSeconds - stopSeconds
    static func remainingStop(after elapsed: TimeInterval) -> TimeInterval {
        min(stopSeconds, max(0, totalSeconds - elapsed))
    }
}

#if Q1C_NATIVE_IMPLEMENTATION || Q1C_OWNER_ADAPTER
// Only a future independently reviewed protected authority verifier may issue this
// value. There is intentionally no initializer accepting JSON, a bool or a digest.
private struct NativeAdmission {
    private init() {}
    static func verify() throws -> NativeAdmission {
        throw ContractError.containmentUnverified
    }
}

// Compiled candidate implementation, not an independently executable VM driver.
// All VZ operations are confined to this retained instance and its serial queue.
// Callback observations never establish physical retirement or per-VM delegate release.
final class NativeVM: NSObject, VZVirtualMachineDelegate, VZVirtioSocketListenerDelegate {
    let queue = DispatchQueue(label: "hermes.q1.exact-vm")
    private let descriptor: Descriptor
    private var configuration: VZVirtualMachineConfiguration?
    private var machine: VZVirtualMachine?
    private var consoleHandles: [FileHandle] = []
    private var sockets: [UInt32: VZVirtioSocketConnection] = [:]
    private var listener: VZVirtioSocketListener?
    private var pendingPorts: Set<UInt32> = []
    private var lifecycle = Lifecycle()
    private var creationSpent = false
    private var bootSpent = false
    private var startPending = false
    private var stopPlan = ExactStopPlan()
    private var startCompletion: ((Error?) -> Void)?
    private var stopCompletion: ((Error?) -> Void)?
    private var windowStarted: TimeInterval?
    private var startDeadline: DispatchWorkItem?
    private var stopDeadline: DispatchWorkItem?
    private var totalDeadline: DispatchWorkItem?
    private var observations: [String] = []

    private init(descriptor: Descriptor, admission: NativeAdmission) {
        self.descriptor = descriptor
        super.init()
    }
    static func acquire(descriptor: Descriptor) throws -> NativeVM {
        // No VZ object or file IO exists before the independent admission gate.
        let admission = try NativeAdmission.verify()
        return NativeVM(descriptor: descriptor, admission: admission)
    }
    private func requireQueue() { dispatchPrecondition(condition: .onQueue(queue)) }
    private func note(_ text: String) {
        // Finite diagnostic facts, never unrestricted Guest text or resource evidence.
        if observations.count < 32 { observations.append(text) }
    }
    private func artifactURL(_ name: String) throws -> URL {
        let pin = try descriptor.artifacts[name]!.object(keys: ["path", "sha256"])
        let path = try pin["path"]!.string()
        let url = URL(fileURLWithPath: path)
        var info = stat()
        guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw ContractError.artifactUnapproved
        }
        // The future authority must independently protect every ancestor and writer.
        // This local digest comparison alone is expressly not that authority.
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hash = SHA256()
        var size: UInt64 = 0
        while let bytes = try handle.read(upToCount: 1_048_576), !bytes.isEmpty {
            if let started = windowStarted, ProcessInfo.processInfo.systemUptime - started >= NativeDeadlines.totalSeconds {
                throw ContractError.stopUncertain
            }
            size += UInt64(bytes.count)
            guard size <= 8_589_934_592 else { throw ContractError.artifactUnapproved }
            hash.update(data: bytes)
        }
        let observed = hash.finalize().map { String(format: "%02x", $0) }.joined()
        guard observed == (try pin["sha256"]!.string()) else { throw ContractError.artifactUnapproved }
        if name == "disk" {
            guard size > 0, size % 512 == 0,
                  size <= UInt64(try descriptor.resources["disk_bytes"]!.integer()) else {
                throw ContractError.artifactUnapproved
            }
        }
        return url
    }
    func create() throws {
        requireQueue()
        guard lifecycle.state == .new, !creationSpent, configuration == nil, machine == nil,
              descriptor.resources["vcpus"] == .integer(2),
              descriptor.resources["memory_bytes"] == .integer(2_147_483_648) else {
            throw ContractError.invalidTransition
        }
        creationSpent = true
        windowStarted = ProcessInfo.processInfo.systemUptime
        let total = DispatchWorkItem { [weak self] in self?.uncertain("TOTAL_WINDOW_STOP_RESERVE") }
        totalDeadline = total
        queue.asyncAfter(deadline: .now() + NativeDeadlines.stopReserveAt, execute: total)
        let kernel = try artifactURL("kernel")
        let initramfs = try artifactURL("initramfs")
        let disk = try artifactURL("disk")
        _ = try artifactURL("policy")
        let share = try descriptor.taskDirectory.object(keys: ["path", "tag", "read_only"])
        let config = VZVirtualMachineConfiguration()
        let boot = VZLinuxBootLoader(kernelURL: kernel)
        boot.initialRamdiskURL = initramfs
        boot.commandLine = "console=hvc0 rdinit=/init panic=-1"
        config.bootLoader = boot
        config.cpuCount = 2
        config.memorySize = 2_147_483_648
        config.networkDevices = []
        config.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        config.storageDevices = [VZVirtioBlockDeviceConfiguration(
            attachment: try VZDiskImageStorageDeviceAttachment(url: disk, readOnly: true))]
        let directory = VZSharedDirectory(url: URL(fileURLWithPath: try share["path"]!.string()), readOnly: true)
        let filesystem = VZVirtioFileSystemDeviceConfiguration(tag: "task")
        filesystem.share = VZSingleDirectoryShare(directory: directory)
        config.directorySharingDevices = [filesystem]
        // No Guest console is forwarded to a terminal or production log. Retain both
        // exact handles through the stop observation; no pipe/thread is hidden here.
        let input = try FileHandle(forReadingFrom: URL(fileURLWithPath: "/dev/null"))
        consoleHandles = [input]
        let output = try FileHandle(forWritingTo: URL(fileURLWithPath: "/dev/null"))
        consoleHandles.append(output)
        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        console.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: input, fileHandleForWriting: output)
        config.serialPorts = [console]
        configuration = config
        try lifecycle.observe(.configured)
        note("CONFIGURED_EXACT_NO_NIC")
    }
    func validateConfiguration() throws {
        requireQueue()
        guard lifecycle.state == .configured, let config = configuration else { throw ContractError.invalidTransition }
        try config.validate()
        // No fallback, repair or unsupported-device substitution.
        guard config.networkDevices.isEmpty, config.socketDevices.count == 1,
              config.directorySharingDevices.count == 1, config.storageDevices.count == 1,
              config.entropyDevices.count == 1, config.serialPorts.count == 1 else {
            lifecycle.invalidate()
            throw ContractError.invalidDescriptor
        }
        let vm = VZVirtualMachine(configuration: config, queue: queue)
        vm.delegate = self
        machine = vm
        try lifecycle.observe(.validated)
        // The inert Guest emits its bounded 4003 observation once during init.
        // Install the exact listener before the Guest can possibly start.
        do { try listenLifecycle() }
        catch { uncertain("LIFECYCLE_LISTENER_ERROR"); throw error }
        note("VZ_VALIDATION_OBSERVED")
    }
    func start(_ completion: @escaping (Error?) -> Void) throws {
        requireQueue()
        guard lifecycle.state == .validated, !bootSpent, let vm = machine else { throw ContractError.invalidTransition }
        bootSpent = true // Spend before crossing the API: callback failure never permits retry.
        startPending = true
        startCompletion = completion
        try lifecycle.observe(.starting)
        let startup = DispatchWorkItem { [weak self] in
            self?.uncertain("START_DEADLINE_EXPIRED")
        }
        startDeadline = startup
        queue.asyncAfter(deadline: .now() + NativeDeadlines.startupSeconds, execute: startup)
        vm.start { [weak self] result in
            guard let self else { return }
            self.startPending = false
            self.startDeadline?.cancel()
            switch result {
            case .success:
                guard self.lifecycle.state == .starting, vm.state == .running else {
                    self.uncertain("LATE_START_OBSERVATION")
                    return
                }
                do { try self.lifecycle.observe(.running); self.note("VZ_RUNNING_OBSERVED"); self.finishStart(nil) }
                catch { self.uncertain("INVALID_START_OBSERVATION") }
            case .failure: self.uncertain("VZ_START_ERROR")
            }
        }
    }
    private func finishStart(_ error: Error?) {
        let callback = startCompletion
        startCompletion = nil
        callback?(error)
    }
    func openOwnerChannel(port: UInt32, completion: @escaping (Error?) -> Void) throws {
        requireQueue()
        guard [4000, 4004].contains(port), lifecycle.state == .running,
              !lifecycle.capabilitiesRevoked, sockets[port] == nil, !pendingPorts.contains(port),
              let device = machine?.socketDevices.first as? VZVirtioSocketDevice else { throw ContractError.channelDenied }
        pendingPorts.insert(port)
        device.connect(toPort: port) { [weak self] result in
            guard let self else { return }
            self.pendingPorts.remove(port)
            switch result {
            case let .success(connection):
                guard self.lifecycle.state == .running, !self.lifecycle.capabilitiesRevoked else {
                    connection.close() // Late acquisition remains attributable to this exact VM.
                    self.uncertain("LATE_SOCKET_AFTER_REVOKE")
                    completion(ContractError.stopUncertain)
                    return
                }
                self.sockets[port] = connection
                self.note("OWNER_CHANNEL_\(port)_OBSERVED")
                completion(nil)
            case let .failure(error): self.uncertain("SOCKET_CONNECT_ERROR"); completion(error)
            }
        }
    }
    func listenLifecycle() throws {
        requireQueue()
        guard [.validated, .starting, .running].contains(lifecycle.state),
              !lifecycle.capabilitiesRevoked, listener == nil,
              let device = machine?.socketDevices.first as? VZVirtioSocketDevice else { throw ContractError.channelDenied }
        let accepted = VZVirtioSocketListener()
        accepted.delegate = self
        listener = accepted
        device.setSocketListener(accepted, forPort: 4003)
    }
    func listener(_ listener: VZVirtioSocketListener, shouldAcceptNewConnection connection: VZVirtioSocketConnection,
                  from socketDevice: VZVirtioSocketDevice) -> Bool {
        requireQueue()
        guard listener === self.listener, socketDevice === machine?.socketDevices.first,
              connection.destinationPort == 4003, [.starting, .running].contains(lifecycle.state),
              !lifecycle.capabilitiesRevoked, sockets[4003] == nil else { return false }
        sockets[4003] = connection
        note("GUEST_DIAGNOSTIC_CHANNEL_OBSERVED_UNTRUSTED")
        return true
    }
    func revoke() {
        requireQueue()
        try? lifecycle.observe(.revoke)
        startDeadline?.cancel()
        if let device = machine?.socketDevices.first as? VZVirtioSocketDevice {
            device.removeSocketListener(forPort: 4003)
        }
        listener?.delegate = nil
        listener = nil
        for connection in sockets.values { connection.close() }
        sockets.removeAll()
        note("ADAPTER_CHANNELS_REVOKED_NOT_INDEPENDENT_PROOF")
    }
    private func uncertain(_ reason: String) {
        requireQueue()
        lifecycle.invalidate()
        revoke()
        note(reason)
        finishStart(ContractError.stopUncertain)
        requestExactStop()
        // No force kill, second native stop attempt, rebind, object discard or successor.
    }
    func stop(_ completion: @escaping (Error?) -> Void) throws {
        requireQueue()
        guard machine != nil, bootSpent, !stopPlan.requested, lifecycle.state != .stoppedObserved else {
            throw ContractError.invalidTransition
        }
        stopCompletion = completion
        revoke()
        finishStart(ContractError.stopUncertain)
        requestExactStop()
    }
    private func finishStop(_ error: Error?) {
        let callback = stopCompletion
        stopCompletion = nil
        callback?(error)
    }
    private func requestExactStop() {
        requireQueue()
        guard let vm = machine else { return }
        let actions = stopPlan.request(bootSpent: bootSpent, startPending: startPending,
                                       observedStopped: vm.state == .stopped, canStop: vm.canStop)
        if actions.armDeadline {
            let deadline = DispatchWorkItem { [weak self] in
                self?.uncertain("STOP_DEADLINE_EXPIRED")
                self?.finishStop(ContractError.stopUncertain)
            }
            stopDeadline = deadline
            // A boot can only follow create(), which stamps windowStarted. Keep the
            // stop callback budget inside that original 300s window, never restart it.
            let remaining = NativeDeadlines.remainingStop(after: ProcessInfo.processInfo.systemUptime - windowStarted!)
            queue.asyncAfter(deadline: .now() + remaining, execute: deadline)
        }
        if actions.closeObservedHandles {
            closeObservedStop()
            return
        }
        guard actions.stopExact else { return }
        // Exact retained VZ object only. No PID/group kill or shared-service termination.
        vm.stop { [weak self] error in
            guard let self else { return }
            guard vm === self.machine else { self.uncertain("STOP_IDENTITY_MISMATCH"); return }
            if let error {
                self.lifecycle.invalidate()
                self.note("VZ_STOP_ERROR")
                self.finishStop(error)
            }
            if vm.state == .stopped && !self.startPending { self.closeObservedStop() }
            else { self.uncertain("STOP_WITNESS_INCOMPLETE") }
        }
    }
    private func closeObservedStop() {
        // Run even after a stop deadline: sticky UNKNOWN must not prevent closure of
        // handles that are now attributable to an observed stopped exact instance.
        do {
            while let handle = consoleHandles.first {
                try handle.close()
                consoleHandles.removeFirst()
            }
            stopDeadline?.cancel()
            totalDeadline?.cancel()
            if !pendingPorts.isEmpty {
                lifecycle.invalidate()
                note("STOP_PENDING_SOCKET_ACQUISITION")
            }
            if lifecycle.state == .revoking { try lifecycle.observe(.stopped) }
            else if ![.stopUncertain, .stoppedObserved].contains(lifecycle.state) { lifecycle.invalidate() }
            note("VZ_STOPPED_OBSERVED_NOT_RETIRED")
            finishStop(lifecycle.state == .stopUncertain ? ContractError.stopUncertain : nil)
        } catch {
            lifecycle.invalidate()
            note("STOP_CLEANUP_ERROR")
            finishStop(error)
        }
    }
    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        requireQueue()
        guard virtualMachine === machine else { uncertain("DELEGATE_IDENTITY_MISMATCH"); return }
        note("GUEST_STOP_CALLBACK_UNTRUSTED_FOR_RETIREMENT")
        if stopPlan.requested { requestExactStop() }
        else { uncertain("UNREQUESTED_GUEST_STOP") }
    }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        requireQueue()
        uncertain(virtualMachine === machine ? "VZ_ERROR_CALLBACK" : "DELEGATE_IDENTITY_MISMATCH")
    }
    func receipt() -> JSONValue {
        requireQueue()
        return .object(["state": .string(lifecycle.state.rawValue), "stop_verified": .bool(false),
                        "per_vm_delegate_rights": .string("UNAVAILABLE"),
                        "independent_resource_witness": .string("UNAVAILABLE"),
                        "observations": .array(observations.map { .string($0) })])
    }
}

// Private inherited-stream framing only: no pathname discovery, listener, ancillary
// FD transfer, stdin bootstrap, ambient HOME, or argv-provided artifact authority.
struct OwnerSocket {
    let fd: Int32
    init(fd: Int32) throws {
        guard fd == 3 else { throw ContractError.nativeNotAuthorized }
        var kind: Int32 = 0
        var length = socklen_t(MemoryLayout.size(ofValue: kind))
        guard getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &length) == 0, kind == SOCK_STREAM else {
            throw ContractError.nativeNotAuthorized
        }
        var address = sockaddr_storage()
        length = socklen_t(MemoryLayout.size(ofValue: address))
        let result = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &length) }
        }
        guard result == 0, address.ss_family == sa_family_t(AF_UNIX) else { throw ContractError.nativeNotAuthorized }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw ContractError.nativeNotAuthorized
        }
        var noSignal: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0 else {
            throw ContractError.nativeNotAuthorized
        }
        self.fd = fd
    }
    private func ready(_ events: Int16, until deadline: TimeInterval) throws {
        while true {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw ContractError.stopUncertain }
            var item = pollfd(fd: fd, events: events, revents: 0)
            let result = poll(&item, 1, Int32(min(5_000, max(1, remaining * 1_000))))
            if result < 0 && errno == EINTR { continue }
            guard result > 0, item.revents & events != 0 else { throw ContractError.stopUncertain }
            return
        }
    }
    private func readExactly(_ count: Int, until deadline: TimeInterval) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            try ready(Int16(POLLIN), until: deadline)
            let result = bytes.withUnsafeMutableBytes { raw in Darwin.read(fd, raw.baseAddress!.advanced(by: offset), count - offset) }
            if result < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard result > 0 else { throw ContractError.stopUncertain }
            offset += result
        }
        return Data(bytes)
    }
    func receive() throws -> Data {
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        let prefix = try readExactly(4, until: deadline)
        let count = prefix.reduce(0) { ($0 << 8) | Int($1) }
        guard count > 0, count <= StrictJSON.frameLimit else { throw ContractError.invalidFrame }
        return try readExactly(count, until: deadline)
    }
    func send(_ value: JSONValue) throws {
        let body = try JSONSerialization.data(withJSONObject: value.foundation, options: [.sortedKeys])
        guard body.count <= StrictJSON.frameLimit else { throw ContractError.invalidFrame }
        let count = UInt32(body.count)
        var bytes = Data([UInt8(count >> 24), UInt8((count >> 16) & 255), UInt8((count >> 8) & 255), UInt8(count & 255)])
        bytes.append(body)
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        try bytes.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                try ready(Int16(POLLOUT), until: deadline)
                let result = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if result < 0 && [EINTR, EAGAIN].contains(errno) { continue }
                guard result > 0 else { throw ContractError.stopUncertain }
                offset += result
            }
        }
    }
}
#endif

#if Q1C_OWNER_ADAPTER
@main enum OwnerAdapter {
    static func main() {
        do {
            // A valid private stream is necessary, never sufficient, for native custody.
            let owner = try OwnerSocket(fd: 3)
            let packet = try decodeJSON(owner.receive()).object(keys: ["descriptor"])
            _ = try Descriptor(Data(packet["descriptor"]!.string().utf8))
            try owner.send(NativeReadiness.denial)
        } catch let error as ContractError {
            // No VZ call occurs on any startup/error path. No stdout protocol fallback.
            let bytes = Data((error.rawValue + "\n").utf8)
            FileHandle.standardError.write(bytes)
        } catch {
            FileHandle.standardError.write(Data("STOP_UNCERTAIN\n".utf8))
        }
    }
}
#endif

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
