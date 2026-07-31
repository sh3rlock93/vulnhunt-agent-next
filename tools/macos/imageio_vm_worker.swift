// Networkless queue worker for the disposable ImageIO research VM.
//
// The host writes opaque inputs and declarative jobs to one VirtioFS bridge.
// This process reconstructs an allow-listed argv, stages the input onto the
// guest filesystem, invokes the bounded job runner, and returns artifacts.

import CryptoKit
import Darwin
import Foundation

let heartbeatSchema = "imageio-vm-heartbeat-v1"
let jobSchema = "imageio-vm-job-v1"
let resultSchema = "imageio-vm-job-result-v1"
let guestInputPath = "/private/tmp/vulnhunt-imageio/input.bin"
let maximumControlBytes = 1024 * 1024

struct Session: Decodable {
    let schemaVersion: String
    let environmentID: String
    let manager: String
    let productVersion: String
    let buildVersion: String
    let architecture: String
    let imageSHA256: String
    let snapshotID: String
    let cloneID: String
    let harnessGuestPath: String

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case environmentID = "environment_id"
        case manager
        case productVersion = "product_version"
        case buildVersion = "build_version"
        case architecture
        case imageSHA256 = "image_sha256"
        case snapshotID = "snapshot_id"
        case cloneID = "clone_id"
        case harnessGuestPath = "harness_guest_path"
    }
}

struct Limits: Codable, Equatable {
    let wallTimeSeconds: Int
    let cpuTimeSeconds: Int
    let maxInputBytes: Int
    let maxProcessMemoryBytes: Int
    let maxOutputBytes: Int
    let maxOpenFiles: Int
    let incrementalChunkBytes: Int
    let maxDecodedBytes: Int

    enum CodingKeys: String, CodingKey {
        case wallTimeSeconds = "wall_time_seconds"
        case cpuTimeSeconds = "cpu_time_seconds"
        case maxInputBytes = "max_input_bytes"
        case maxProcessMemoryBytes = "max_process_memory_bytes"
        case maxOutputBytes = "max_output_bytes"
        case maxOpenFiles = "max_open_files"
        case incrementalChunkBytes = "incremental_chunk_bytes"
        case maxDecodedBytes = "max_decoded_bytes"
    }

    func validate() throws {
        let values = [
            wallTimeSeconds,
            cpuTimeSeconds,
            maxInputBytes,
            maxProcessMemoryBytes,
            maxOutputBytes,
            maxOpenFiles,
            incrementalChunkBytes,
            maxDecodedBytes,
        ]
        guard values.allSatisfy({ $0 > 0 }), cpuTimeSeconds <= wallTimeSeconds else {
            throw WorkerError.invalidRequest("resource limits are invalid")
        }
    }
}

struct CanaryInterposer: Codable, Equatable {
    let schemaVersion: String
    let sourceRevision: String
    let binarySHA256: String
    let guestPath: String
    let canaryValue: Int
    let minimumAllocationBytes: Int
    let maximumAllocationBytes: Int
    let humanReviewApproved: Bool
    let hostInjectionAllowed: Bool
    let thirdPartyInjectionAllowed: Bool

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case sourceRevision = "source_revision"
        case binarySHA256 = "binary_sha256"
        case guestPath = "guest_path"
        case canaryValue = "canary_value"
        case minimumAllocationBytes = "minimum_allocation_bytes"
        case maximumAllocationBytes = "maximum_allocation_bytes"
        case humanReviewApproved = "human_review_approved"
        case hostInjectionAllowed = "host_injection_allowed"
        case thirdPartyInjectionAllowed = "third_party_injection_allowed"
    }
}

struct JobRequest: Decodable {
    let schemaVersion: String
    let jobID: String
    let environmentID: String
    let bootID: String
    let route: String
    let inputSHA256: String
    let inputSizeBytes: Int
    let guestInputPath: String
    let argv: [String]
    let limits: Limits
    let canaryInterposer: CanaryInterposer?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case jobID = "job_id"
        case environmentID = "environment_id"
        case bootID = "boot_id"
        case route
        case inputSHA256 = "input_sha256"
        case inputSizeBytes = "input_size_bytes"
        case guestInputPath = "guest_input_path"
        case argv
        case limits
        case canaryInterposer = "canary_interposer"
    }
}

enum WorkerError: Error, CustomStringConvertible {
    case invalidArguments
    case invalidRequest(String)
    case commandFailed(String)

    var description: String {
        switch self {
        case .invalidArguments:
            return "usage: imageio-vm-worker --bridge PATH"
        case .invalidRequest(let message), .commandFailed(let message):
            return message
        }
    }
}

func parseBridgePath() throws -> URL {
    let arguments = CommandLine.arguments
    guard arguments.count == 3, arguments[1] == "--bridge" else {
        throw WorkerError.invalidArguments
    }
    let path = arguments[2]
    guard path.hasPrefix("/"), !path.contains(".."), !path.contains("\0") else {
        throw WorkerError.invalidArguments
    }
    return URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL
}

func readBounded(_ url: URL, maximum: Int = maximumControlBytes) throws -> Data {
    let values = try url.resourceValues(forKeys: [
        .isRegularFileKey,
        .isSymbolicLinkKey,
        .fileSizeKey,
    ])
    guard values.isRegularFile == true, values.isSymbolicLink != true else {
        throw WorkerError.invalidRequest("bridge input is not a regular file")
    }
    guard let size = values.fileSize, size <= maximum else {
        throw WorkerError.invalidRequest("bridge input exceeds its byte limit")
    }
    return try Data(contentsOf: url, options: [.mappedIfSafe])
}

func decode<T: Decodable>(_ type: T.Type, from url: URL) throws -> T {
    try JSONDecoder().decode(type, from: readBounded(url))
}

func sha256(_ url: URL) throws -> String {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    var hasher = SHA256()
    while let chunk = try handle.read(upToCount: 1024 * 1024), !chunk.isEmpty {
        hasher.update(data: chunk)
    }
    return "sha256:" + hasher.finalize().map { String(format: "%02x", $0) }.joined()
}

func runCommand(_ executable: String, _ arguments: [String]) throws -> Data {
    let process = Process()
    let output = Pipe()
    let error = Pipe()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = output
    process.standardError = error
    try process.run()
    process.waitUntilExit()
    let stdout = output.fileHandleForReading.readDataToEndOfFile()
    let stderr = error.fileHandleForReading.readDataToEndOfFile()
    guard process.terminationReason == .exit, process.terminationStatus == 0 else {
        let message = String(data: stderr, encoding: .utf8) ?? "command failed"
        throw WorkerError.commandFailed(message.trimmingCharacters(in: .whitespacesAndNewlines))
    }
    return stdout
}

func swVers(_ option: String) throws -> String {
    let data = try runCommand("/usr/bin/sw_vers", [option])
    guard let value = String(data: data, encoding: .utf8)?
        .trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
        throw WorkerError.commandFailed("sw_vers returned no value")
    }
    return value
}

func bootSessionID() throws -> String {
    let name = "kern.bootsessionuuid"
    var size = 0
    guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 1 else {
        throw WorkerError.commandFailed("cannot read boot session UUID")
    }
    var buffer = [CChar](repeating: 0, count: size)
    guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else {
        throw WorkerError.commandFailed("cannot read boot session UUID")
    }
    return String(cString: buffer)
}

func atomicWriteJSON(_ payload: [String: Any], to url: URL) throws {
    let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    try data.write(to: url, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}

func validJobID(_ value: String) -> Bool {
    value.count == 32 && value.allSatisfy { character in
        character.isNumber || (character >= "a" && character <= "f")
    }
}

func allowedRoute(_ value: String) -> Bool {
    [
        "data_properties",
        "image_properties",
        "thumbnail_decode",
        "full_decode",
        "incremental_decode",
        "raw_pixel_copy",
    ].contains(value)
}

func expectedArgv(session: Session, request: JobRequest) -> [String] {
    [
        session.harnessGuestPath,
        "--route", request.route,
        "--input", guestInputPath,
        "--chunk-size", String(request.limits.incrementalChunkBytes),
        "--max-input-bytes", String(request.limits.maxInputBytes),
        "--max-decoded-bytes", String(request.limits.maxDecodedBytes),
        "--wall-time-seconds", String(request.limits.wallTimeSeconds),
        "--cpu-time-seconds", String(request.limits.cpuTimeSeconds),
        "--max-process-memory-bytes", String(request.limits.maxProcessMemoryBytes),
        "--max-open-files", String(request.limits.maxOpenFiles),
    ]
}

func validate(
    request: JobRequest,
    session: Session,
    bootID: String,
    jobDirectory: URL,
    harnessURL: URL,
    binDirectory: URL
) throws -> String {
    guard request.schemaVersion == jobSchema,
          validJobID(request.jobID),
          request.jobID == jobDirectory.lastPathComponent,
          request.environmentID == session.environmentID,
          request.bootID == bootID,
          allowedRoute(request.route),
          request.guestInputPath == guestInputPath,
          request.inputSizeBytes >= 0 else {
        throw WorkerError.invalidRequest("job identity or route is invalid")
    }
    try request.limits.validate()
    guard request.inputSizeBytes <= request.limits.maxInputBytes else {
        throw WorkerError.invalidRequest("input exceeds the requested limit")
    }
    guard session.harnessGuestPath == harnessURL.path,
          request.argv == expectedArgv(session: session, request: request) else {
        throw WorkerError.invalidRequest("job argv does not match the fixed harness contract")
    }
    let inputURL = jobDirectory.appendingPathComponent("input.bin")
    let attributes = try inputURL.resourceValues(forKeys: [
        .isRegularFileKey,
        .isSymbolicLinkKey,
        .fileSizeKey,
    ])
    guard attributes.isRegularFile == true,
          attributes.isSymbolicLink != true,
          attributes.fileSize == request.inputSizeBytes else {
        throw WorkerError.invalidRequest("staged input metadata is invalid")
    }
    let digest = try sha256(inputURL)
    guard digest == request.inputSHA256 else {
        throw WorkerError.invalidRequest("staged input digest mismatch")
    }
    if let canary = request.canaryInterposer {
        let interposerURL = binDirectory.appendingPathComponent(
            "imageio-canary-interposer.dylib"
        )
        guard request.route == "raw_pixel_copy",
              canary.schemaVersion == "imageio-canary-interposer-v1",
              canary.sourceRevision == "m16-canary-interposer-v1",
              canary.guestPath == interposerURL.path,
              canary.humanReviewApproved,
              !canary.hostInjectionAllowed,
              !canary.thirdPartyInjectionAllowed,
              (0...255).contains(canary.canaryValue),
              canary.minimumAllocationBytes > 0,
              canary.minimumAllocationBytes <= canary.maximumAllocationBytes,
              canary.maximumAllocationBytes <= request.limits.maxDecodedBytes,
              try sha256(interposerURL) == canary.binarySHA256 else {
            throw WorkerError.invalidRequest("canary interposer identity is invalid")
        }
    }
    return digest
}

func makeFailureResult(
    request: JobRequest,
    bootID: String,
    digest: String,
    message: String
) -> [String: Any] {
    var result: [String: Any] = [
        "schema_version": resultSchema,
        "job_id": request.jobID,
        "environment_id": request.environmentID,
        "boot_id": bootID,
        "argv": request.argv,
        "guest_input_sha256": digest,
        "enforced_limits": try! JSONSerialization.jsonObject(
            with: JSONEncoder().encode(request.limits)
        ),
        "exit_code": NSNull(),
        "terminating_signal": NSNull(),
        "timed_out": false,
        "memory_limit_exceeded": false,
        "launch_error": message,
        "duration_ms": 0,
        "crash_log_present": false,
        "crash_log_truncated": false,
    ]
    if let canary = request.canaryInterposer {
        result["canary_interposer_sha256"] = canary.binarySHA256
        result["canary_value"] = canary.canaryValue
    } else {
        result["canary_interposer_sha256"] = NSNull()
        result["canary_value"] = NSNull()
    }
    return result
}

func processJob(
    _ jobDirectory: URL,
    bridge: URL,
    session: Session,
    bootID: String,
    binDirectory: URL
) {
    let fileManager = FileManager.default
    let outbox = bridge.appendingPathComponent("outbox", isDirectory: true)
    let finalResult = outbox.appendingPathComponent(jobDirectory.lastPathComponent, isDirectory: true)
    if fileManager.fileExists(atPath: finalResult.path) {
        return
    }
    let temporaryResult = outbox.appendingPathComponent(
        ".\(jobDirectory.lastPathComponent).\(UUID().uuidString).tmp",
        isDirectory: true
    )
    var request: JobRequest?
    var digest = "sha256:" + String(repeating: "0", count: 64)
    do {
        try fileManager.createDirectory(
            at: temporaryResult,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let decoded = try decode(
            JobRequest.self,
            from: jobDirectory.appendingPathComponent("request.json")
        )
        request = decoded
        let harnessURL = binDirectory.appendingPathComponent("imageio-harness")
        let jobRunnerURL = binDirectory.appendingPathComponent("imageio-job-runner")
        digest = try validate(
            request: decoded,
            session: session,
            bootID: bootID,
            jobDirectory: jobDirectory,
            harnessURL: harnessURL,
            binDirectory: binDirectory
        )

        let localDirectory = URL(fileURLWithPath: "/private/tmp/vulnhunt-imageio", isDirectory: true)
        try fileManager.createDirectory(
            at: localDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let localInput = URL(fileURLWithPath: guestInputPath)
        try? fileManager.removeItem(at: localInput)
        try fileManager.copyItem(
            at: jobDirectory.appendingPathComponent("input.bin"),
            to: localInput
        )
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: localInput.path)

        let argv = expectedArgv(session: session, request: decoded)
        var runnerArguments = [
            "--expected-input-sha256", decoded.inputSHA256,
            "--wall-time-seconds", String(decoded.limits.wallTimeSeconds),
            "--cpu-time-seconds", String(decoded.limits.cpuTimeSeconds),
            "--max-process-memory-bytes", String(decoded.limits.maxProcessMemoryBytes),
            "--max-output-bytes", String(decoded.limits.maxOutputBytes),
            "--max-open-files", String(decoded.limits.maxOpenFiles),
        ]
        if let canary = decoded.canaryInterposer {
            runnerArguments += [
                "--canary-interposer", canary.guestPath,
                "--canary-interposer-sha256", canary.binarySHA256,
                "--canary-value", String(canary.canaryValue),
                "--canary-minimum-allocation-bytes", String(canary.minimumAllocationBytes),
                "--canary-maximum-allocation-bytes", String(canary.maximumAllocationBytes),
            ]
        }
        runnerArguments += ["--"] + argv
        let runnerData = try runCommand(jobRunnerURL.path, runnerArguments)
        guard var runner = try JSONSerialization.jsonObject(with: runnerData) as? [String: Any] else {
            throw WorkerError.commandFailed("job runner returned invalid JSON")
        }
        for name in ["stdout.bin", "stderr.bin", "crash.log"] {
            let source = localDirectory.appendingPathComponent(name)
            if fileManager.fileExists(atPath: source.path) {
                try fileManager.copyItem(
                    at: source,
                    to: temporaryResult.appendingPathComponent(name)
                )
            }
        }
        runner["schema_version"] = resultSchema
        runner["job_id"] = decoded.jobID
        runner["environment_id"] = decoded.environmentID
        runner["boot_id"] = bootID
        runner["argv"] = argv
        runner["guest_input_sha256"] = runner.removeValue(forKey: "input_sha256")
        runner["enforced_limits"] = try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(decoded.limits)
        )
        runner["launch_error"] = NSNull()
        runner.removeValue(forKey: "argv_sha256")
        runner.removeValue(forKey: "wall_time_seconds")
        runner.removeValue(forKey: "cpu_time_seconds")
        runner.removeValue(forKey: "max_process_memory_bytes")
        runner.removeValue(forKey: "max_output_bytes")
        runner.removeValue(forKey: "max_open_files")
        try atomicWriteJSON(runner, to: temporaryResult.appendingPathComponent("result.json"))
        try fileManager.moveItem(at: temporaryResult, to: finalResult)
    } catch {
        guard let decoded = request else {
            try? fileManager.removeItem(at: temporaryResult)
            return
        }
        let message = String(describing: error).prefix(500)
        let result = makeFailureResult(
            request: decoded,
            bootID: bootID,
            digest: digest,
            message: String(message)
        )
        try? atomicWriteJSON(result, to: temporaryResult.appendingPathComponent("result.json"))
        try? Data().write(to: temporaryResult.appendingPathComponent("stdout.bin"))
        try? Data().write(to: temporaryResult.appendingPathComponent("stderr.bin"))
        try? fileManager.moveItem(at: temporaryResult, to: finalResult)
    }
}

func writeHeartbeat(
    bridge: URL,
    session: Session,
    bootID: String,
    workerURL: URL,
    binDirectory: URL
) throws {
    let productVersion = try swVers("-productVersion")
    let buildVersion = try swVers("-buildVersion")
    guard session.schemaVersion == "imageio-vm-session-v1",
          session.architecture == "arm64",
          productVersion == session.productVersion,
          buildVersion == session.buildVersion else {
        throw WorkerError.invalidRequest("guest build does not match the frozen session")
    }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let heartbeat: [String: Any] = [
        "schema_version": heartbeatSchema,
        "environment_id": session.environmentID,
        "manager": session.manager,
        "product_version": productVersion,
        "build_version": buildVersion,
        "architecture": "arm64",
        "image_sha256": session.imageSHA256,
        "snapshot_id": session.snapshotID,
        "clone_id": session.cloneID,
        "boot_id": bootID,
        "observed_at": formatter.string(from: Date()),
        "execution_boundary": "macos_virtual_machine",
        "executed_on_host": false,
        "worker_sha256": try sha256(workerURL),
        "harness_sha256": try sha256(binDirectory.appendingPathComponent("imageio-harness")),
        "job_runner_sha256": try sha256(
            binDirectory.appendingPathComponent("imageio-job-runner")
        ),
        "canary_interposer_sha256": try sha256(
            binDirectory.appendingPathComponent("imageio-canary-interposer.dylib")
        ),
    ]
    try atomicWriteJSON(
        heartbeat,
        to: bridge.appendingPathComponent("control/heartbeat.json")
    )
}

do {
    let bridge = try parseBridgePath()
    let workerURL = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    let binDirectory = workerURL.deletingLastPathComponent()
    let bootID = try bootSessionID()
    var lastHeartbeat = Date.distantPast
    while true {
        autoreleasepool {
            do {
                let session = try decode(
                    Session.self,
                    from: bridge.appendingPathComponent("control/session.json")
                )
                if Date().timeIntervalSince(lastHeartbeat) >= 1 {
                    try writeHeartbeat(
                        bridge: bridge,
                        session: session,
                        bootID: bootID,
                        workerURL: workerURL,
                        binDirectory: binDirectory
                    )
                    lastHeartbeat = Date()
                }
                let inbox = bridge.appendingPathComponent("inbox", isDirectory: true)
                for item in try FileManager.default.contentsOfDirectory(
                    at: inbox,
                    includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
                    options: [.skipsHiddenFiles]
                ) {
                    let values = try item.resourceValues(forKeys: [
                        .isDirectoryKey,
                        .isSymbolicLinkKey,
                    ])
                    guard values.isDirectory == true,
                          values.isSymbolicLink != true,
                          validJobID(item.lastPathComponent) else {
                        continue
                    }
                    processJob(
                        item,
                        bridge: bridge,
                        session: session,
                        bootID: bootID,
                        binDirectory: binDirectory
                    )
                }
            } catch {
                // The bridge can appear after login.  Fail closed and retry;
                // never execute a job without a valid frozen session.
            }
        }
        Thread.sleep(forTimeInterval: 0.2)
    }
} catch {
    FileHandle.standardError.write(Data((String(describing: error) + "\n").utf8))
    exit(64)
}
