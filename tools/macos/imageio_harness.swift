// Standalone ImageIO exercise harness for disposable arm64 macOS VMs.
//
// The control plane supplies a fixed local file path and enforces process
// limits.  This program performs no network operations and never accepts a URL.

import CoreGraphics
import Darwin
import Foundation
import ImageIO

enum HarnessRoute: String {
    case dataProperties = "data_properties"
    case imageProperties = "image_properties"
    case thumbnailDecode = "thumbnail_decode"
    case fullDecode = "full_decode"
    case incrementalDecode = "incremental_decode"
}

struct Arguments {
    let route: HarnessRoute
    let inputPath: String
    let chunkSize: Int
    let maxInputBytes: Int
    let maxDecodedBytes: Int
}

func fail(_ message: String, code: Int32 = 64) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

func parsePositiveInt(_ value: String, label: String) -> Int {
    guard let parsed = Int(value), parsed > 0 else {
        fail("\(label) must be a positive integer")
    }
    return parsed
}

func parseArguments() -> Arguments {
    var values: [String: String] = [:]
    var index = 1
    while index < CommandLine.arguments.count {
        let key = CommandLine.arguments[index]
        guard key.hasPrefix("--"), index + 1 < CommandLine.arguments.count else {
            fail("arguments must be --name value pairs")
        }
        guard values[key] == nil else {
            fail("duplicate argument: \(key)")
        }
        values[key] = CommandLine.arguments[index + 1]
        index += 2
    }
    let expected = Set([
        "--route",
        "--input",
        "--chunk-size",
        "--max-input-bytes",
        "--max-decoded-bytes",
    ])
    guard Set(values.keys) == expected else {
        fail("required arguments: \(expected.sorted().joined(separator: ", "))")
    }
    guard let routeValue = values["--route"], let route = HarnessRoute(rawValue: routeValue) else {
        fail("unsupported ImageIO route")
    }
    guard let inputPath = values["--input"], inputPath.hasPrefix("/") else {
        fail("input must be an absolute local path")
    }
    guard !inputPath.contains(".."), !inputPath.contains("\0") else {
        fail("input path is not normalized")
    }
    return Arguments(
        route: route,
        inputPath: inputPath,
        chunkSize: parsePositiveInt(values["--chunk-size"]!, label: "chunk size"),
        maxInputBytes: parsePositiveInt(
            values["--max-input-bytes"]!,
            label: "maximum input bytes"
        ),
        maxDecodedBytes: parsePositiveInt(
            values["--max-decoded-bytes"]!,
            label: "maximum decoded bytes"
        )
    )
}

func emit(_ payload: [String: Any]) {
    do {
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    } catch {
        fail("failed to serialize harness result", code: 70)
    }
}

func sourceSummary(_ source: CGImageSource) -> [String: Any] {
    var result: [String: Any] = [
        "source_created": true,
        "image_count": CGImageSourceGetCount(source),
        "status": CGImageSourceGetStatus(source).rawValue,
    ]
    if let type = CGImageSourceGetType(source) {
        result["type_identifier"] = type as String
    }
    return result
}

func checkedDecodedSize(width: Int, height: Int, maximum: Int) -> Int? {
    guard width > 0, height > 0 else {
        return nil
    }
    let (bytesPerRow, rowOverflow) = width.multipliedReportingOverflow(by: 4)
    let (totalBytes, totalOverflow) = bytesPerRow.multipliedReportingOverflow(by: height)
    guard !rowOverflow, !totalOverflow, totalBytes <= maximum else {
        return nil
    }
    return totalBytes
}

func forceDecode(_ image: CGImage, maximumBytes: Int) -> [String: Any] {
    let width = image.width
    let height = image.height
    var result: [String: Any] = ["width": width, "height": height]
    guard let totalBytes = checkedDecodedSize(
        width: width,
        height: height,
        maximum: maximumBytes
    ) else {
        result["pixels_rendered"] = false
        result["decode_skip_reason"] = "decoded dimensions exceed limit"
        return result
    }

    let bytesPerRow = width * 4
    var pixels = [UInt8](repeating: 0, count: totalBytes)
    let rendered = pixels.withUnsafeMutableBytes { rawBuffer -> Bool in
        guard let baseAddress = rawBuffer.baseAddress else {
            return false
        }
        guard let context = CGContext(
            data: baseAddress,
            width: width,
            height: height,
            bitsPerComponent: 8,
            bytesPerRow: bytesPerRow,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ) else {
            return false
        }
        context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
        return true
    }
    result["pixels_rendered"] = rendered
    result["decoded_bytes"] = totalBytes
    return result
}

func withSource(
    data: Data,
    route: HarnessRoute,
    body: (CGImageSource) -> [String: Any]
) -> [String: Any] {
    guard let source = CGImageSourceCreateWithData(data as CFData, nil) else {
        return ["route": route.rawValue, "source_created": false]
    }
    var result = sourceSummary(source)
    result["route"] = route.rawValue
    for (key, value) in body(source) {
        result[key] = value
    }
    return result
}

func runNonIncremental(_ arguments: Arguments, data: Data) -> [String: Any] {
    switch arguments.route {
    case .dataProperties:
        return withSource(data: data, route: arguments.route) { source in
            let properties = CGImageSourceCopyProperties(source, nil)
            return [
                "properties_available": properties != nil,
                "property_count": properties.map(CFDictionaryGetCount) ?? 0,
            ]
        }
    case .imageProperties:
        return withSource(data: data, route: arguments.route) { source in
            guard CGImageSourceGetCount(source) > 0 else {
                return ["properties_available": false, "property_count": 0]
            }
            let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil)
            return [
                "properties_available": properties != nil,
                "property_count": properties.map(CFDictionaryGetCount) ?? 0,
            ]
        }
    case .thumbnailDecode:
        return withSource(data: data, route: arguments.route) { source in
            guard CGImageSourceGetCount(source) > 0 else {
                return ["thumbnail_created": false]
            }
            let options: [CFString: Any] = [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceCreateThumbnailWithTransform: true,
                kCGImageSourceThumbnailMaxPixelSize: 1024,
            ]
            guard let image = CGImageSourceCreateThumbnailAtIndex(
                source,
                0,
                options as CFDictionary
            ) else {
                return ["thumbnail_created": false]
            }
            var result = forceDecode(image, maximumBytes: arguments.maxDecodedBytes)
            result["thumbnail_created"] = true
            return result
        }
    case .fullDecode:
        return withSource(data: data, route: arguments.route) { source in
            guard CGImageSourceGetCount(source) > 0,
                  let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else {
                return ["image_created": false]
            }
            var result = forceDecode(image, maximumBytes: arguments.maxDecodedBytes)
            result["image_created"] = true
            return result
        }
    case .incrementalDecode:
        fail("incremental route reached non-incremental dispatcher", code: 70)
    }
}

func runIncremental(_ arguments: Arguments, data: Data) -> [String: Any] {
    let source = CGImageSourceCreateIncremental(nil)
    var updates = 0
    var statuses: [Int32] = []

    if data.isEmpty {
        CGImageSourceUpdateData(source, data as CFData, true)
        updates = 1
        statuses.append(CGImageSourceGetStatus(source).rawValue)
    } else {
        var end = min(arguments.chunkSize, data.count)
        while true {
            let prefix = Data(data.prefix(end))
            let isFinal = end == data.count
            CGImageSourceUpdateData(source, prefix as CFData, isFinal)
            updates += 1
            statuses.append(CGImageSourceGetStatus(source).rawValue)
            if isFinal {
                break
            }
            end = min(end + arguments.chunkSize, data.count)
        }
    }

    var result = sourceSummary(source)
    result["route"] = arguments.route.rawValue
    result["update_count"] = updates
    result["statuses"] = statuses
    if CGImageSourceGetCount(source) > 0,
       let image = CGImageSourceCreateImageAtIndex(source, 0, nil) {
        result["image_created"] = true
        for (key, value) in forceDecode(image, maximumBytes: arguments.maxDecodedBytes) {
            result[key] = value
        }
    } else {
        result["image_created"] = false
    }
    return result
}

let arguments = parseArguments()
let inputURL = URL(fileURLWithPath: arguments.inputPath, isDirectory: false)
let attributes: [FileAttributeKey: Any]
do {
    attributes = try FileManager.default.attributesOfItem(atPath: arguments.inputPath)
} catch {
    fail("cannot inspect input file", code: 66)
}
guard attributes[.type] as? FileAttributeType == .typeRegular else {
    fail("input must be a regular file", code: 66)
}
guard let fileSize = attributes[.size] as? NSNumber,
      fileSize.uint64Value <= UInt64(arguments.maxInputBytes) else {
    fail("input exceeds maximum byte limit", code: 66)
}
let data: Data
do {
    data = try Data(contentsOf: inputURL, options: [.mappedIfSafe])
} catch {
    fail("cannot read input file", code: 66)
}

let result: [String: Any]
if arguments.route == .incrementalDecode {
    result = runIncremental(arguments, data: data)
} else {
    result = runNonIncremental(arguments, data: data)
}
emit(result)
