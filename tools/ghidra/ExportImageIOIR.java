// Export bounded decompiler evidence for the M14 normalized-IR adapter.
// @category VulnHunt

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class ExportImageIOIR extends GhidraScript {
	private static final int MAX_PSEUDOCODE_CHARS = 240000;
	private static final int MAX_CENSUS_EDGES = 128;
	private static final int MAX_DIRECT_STRINGS = 256;
	private static final Set<String> PARSER_MARKERS = Set.of(
		"decode", "decoder", "parse", "parser", "reader", "read", "decompress",
		"rle", "tiff", "dng", "jpeg", "jp2", "png", "gif", "heif", "webp",
		"dicom", "sgi");
	private static final Set<String> NAME_ACTION_MARKERS = Set.of(
		"decode", "decoder", "parse", "parser", "reader", "read", "decompress",
		"rle");
	private static final Set<String> EVIDENCE_STRING_MARKERS = Set.of(
		"decode", "decoder", "decompress", "compressed", "malformed", "corrupt",
		"rle", "tiff", "dng", "jpeg", "jp2", "png", "gif", "heif", "webp",
		"dicom", "sgi");
	private static final Set<String> RANGE_READER_IDENTITIES = Set.of(
		"getbytesatoffset", "iioimagereadsessiongetbytesatoffset",
		"cgimagereadsessiongetbytesatoffset");

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 8) {
			throw new IllegalArgumentException(
				"usage: ExportImageIOIR.java <output> <snapshot-sha256> <image-uuid> " +
				"<max-functions> <max-ops-per-function> <decompile-seconds> " +
				"<coverage-depth> <max-evidence-functions>");
		}
		File output = new File(args[0]).getCanonicalFile();
		String snapshot = args[1];
		String imageUuid = args[2].toUpperCase(Locale.ROOT);
		int maxFunctions = boundedInt(args[3], "max-functions", 1, 10000);
		int maxOps = boundedInt(args[4], "max-ops-per-function", 1, 9990);
		int decompileSeconds = boundedInt(args[5], "decompile-seconds", 1, 120);
		int coverageDepth = boundedInt(args[6], "coverage-depth", 0, 8);
		int maxEvidenceFunctions = boundedInt(
			args[7], "max-evidence-functions", 1, 10000);
		if (!snapshot.matches("sha256:[0-9a-f]{64}")) {
			throw new IllegalArgumentException("invalid snapshot digest");
		}
		if (!imageUuid.matches("[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")) {
			throw new IllegalArgumentException("invalid Mach-O UUID");
		}
		if (output.exists()) {
			throw new IllegalArgumentException("refusing to replace output: " + output);
		}
		if (output.getParentFile() == null || !output.getParentFile().isDirectory()) {
			throw new IllegalArgumentException("output parent must already exist");
		}

		JsonObject root = new JsonObject();
		root.addProperty("schema_version", "ghidra-imageio-export-v3");
		root.addProperty("decompiler_version", Application.getApplicationVersion());
		root.addProperty("snapshot_sha256", snapshot);
		JsonObject image = new JsonObject();
		image.addProperty("name", currentProgram.getName());
		image.addProperty("uuid", imageUuid);
		image.addProperty("architecture", architecture());
		image.addProperty("base_address", address(currentProgram.getImageBase()));
		root.add("image", image);
		root.add("imports", imports());
		Census census = census(20000);
		root.add("strings", census.strings);
		List<CoverageRow> selected = selectFunctions(
			census.rows, maxFunctions, coverageDepth, maxEvidenceFunctions);
		root.add("function_coverage", coverageManifest(
			census.rows, selected, snapshot, maxFunctions, coverageDepth,
			maxEvidenceFunctions));
		root.add("virtual_methods", virtualMethodReferences(selected));

		DecompInterface decompiler = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		decompiler.setOptions(options);
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");
		if (!decompiler.openProgram(currentProgram)) {
			throw new IllegalStateException("decompiler initialization failed: " + decompiler.getLastMessage());
		}
		try {
			JsonArray functions = new JsonArray();
			monitor.initialize(selected.size(), "Exporting bounded ImageIO IR");
			for (CoverageRow row : selected) {
				monitor.checkCancelled();
				functions.add(exportFunction(
					decompiler, row.function, maxOps, decompileSeconds));
				monitor.incrementProgress(1);
			}
			if (functions.isEmpty()) {
				throw new IllegalStateException("program contains no exportable functions");
			}
			root.add("functions", functions);
		}
		finally {
			decompiler.dispose();
		}

		Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
		try (FileWriter writer = new FileWriter(output, StandardCharsets.UTF_8)) {
			gson.toJson(root, writer);
			writer.write("\n");
		}
		try {
			Files.setPosixFilePermissions(output.toPath(), Set.of(
				PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
		}
		catch (UnsupportedOperationException ignored) {
			output.setReadable(false, false);
			output.setReadable(true, true);
			output.setWritable(false, false);
			output.setWritable(true, true);
		}
		println("Exported " + root.getAsJsonArray("functions").size() +
			" functions to " + output);
	}

	private JsonObject exportFunction(DecompInterface decompiler, Function function,
			int maxOps, int decompileSeconds) {
		long entry = function.getEntryPoint().getOffset();
		long max = Math.max(entry, function.getBody().getMaxAddress().getOffset());
		JsonObject json = new JsonObject();
		json.addProperty("entry", hex(entry));
		json.addProperty("size", Math.max(1L, max - entry + 1L));
		json.addProperty("name", function.getName());
		JsonArray parameters = new JsonArray();
		for (Parameter parameter : function.getParameters()) {
			parameters.add(parameterName(parameter));
		}
		json.add("parameters", parameters);

		DecompileResults result = decompiler.decompileFunction(function, decompileSeconds, monitor);
		String pseudocode = "";
		if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
			pseudocode = result.getDecompiledFunction().getC().strip();
			if (pseudocode.length() > MAX_PSEUDOCODE_CHARS) {
				pseudocode = pseudocode.substring(0, MAX_PSEUDOCODE_CHARS);
			}
		}
		json.addProperty("pseudocode", pseudocode);
		HighFunction high = result == null ? null : result.getHighFunction();
		json.add("blocks", exportBlocks(function, high, maxOps));
		return json;
	}

	private JsonArray exportBlocks(Function function, HighFunction high, int maxOps) {
		JsonArray blocks = new JsonArray();
		long functionStart = function.getEntryPoint().getOffset();
		long functionEnd = Math.max(functionStart, function.getBody().getMaxAddress().getOffset());
		if (high == null || high.getBasicBlocks().isEmpty()) {
			blocks.add(placeholderBlock(functionStart, functionEnd));
			return blocks;
		}

		List<PcodeBlockBasic> valid = new ArrayList<>();
		for (PcodeBlockBasic block : high.getBasicBlocks()) {
			if (block.getStart() != null && block.getStart().getOffset() >= functionStart &&
					block.getStart().getOffset() <= functionEnd) {
				valid.add(block);
			}
		}
		valid.sort(Comparator.comparingLong(block -> block.getStart().getOffset()));
		if (valid.isEmpty()) {
			blocks.add(placeholderBlock(functionStart, functionEnd));
			return blocks;
		}
		Set<PcodeBlockBasic> validSet = new HashSet<>(valid);
		int remaining = maxOps;
		for (int ordinal = 0; ordinal < valid.size(); ordinal++) {
			PcodeBlockBasic block = valid.get(ordinal);
			long start = block.getStart().getOffset();
			long stop = block.getStop() == null ? start : block.getStop().getOffset();
			stop = Math.min(functionEnd, Math.max(start, stop));
			JsonObject json = new JsonObject();
			json.addProperty("name", blockName(ordinal, start));
			json.addProperty("start", hex(start));
			json.addProperty("size", Math.max(1L, stop - start + 1L));
			JsonArray successors = new JsonArray();
			for (int index = 0; index < block.getOutSize(); index++) {
				PcodeBlock target = block.getOut(index);
				if (target instanceof PcodeBlockBasic && validSet.contains(target)) {
					PcodeBlockBasic basic = (PcodeBlockBasic) target;
					int targetOrdinal = valid.indexOf(basic);
					successors.add(blockName(targetOrdinal, basic.getStart().getOffset()));
				}
			}
			json.add("successors", successors);

			JsonArray instructions = new JsonArray();
			if (ordinal == 0) {
				for (Parameter parameter : function.getParameters()) {
					if (remaining <= 0) break;
					instructions.add(parameterInstruction(function, parameter, start));
					remaining--;
				}
			}
			List<PcodeOp> orderedOperations = new ArrayList<>();
			Iterator<PcodeOp> operations = block.getIterator();
			while (operations.hasNext()) orderedOperations.add(operations.next());
			orderedOperations.sort(Comparator
				.comparingLong((PcodeOp operation) -> operation.getSeqnum().getTarget().getOffset())
				.thenComparingInt(operation -> operation.getSeqnum().getTime()));
			for (PcodeOp operation : orderedOperations) {
				if (remaining <= 0) break;
				long opAddress = operation.getSeqnum().getTarget().getOffset();
				if (opAddress >= start && opAddress <= stop) {
					instructions.add(exportOperation(operation));
					remaining--;
				}
			}
			if (instructions.isEmpty()) {
				instructions.add(placeholderInstruction(start));
			}
			json.add("instructions", instructions);
			blocks.add(json);
		}
		return blocks;
	}

	private JsonObject exportOperation(PcodeOp operation) {
		JsonObject json = new JsonObject();
		long at = operation.getSeqnum().getTarget().getOffset();
		String mnemonic = operation.getMnemonic().toUpperCase(Locale.ROOT);
		String callee = null;
		int inputStart = 0;
		if (mnemonic.equals("CALL") || mnemonic.equals("CALLIND")) {
			callee = resolveCallee(operation);
			inputStart = 1;
		}
		json.addProperty("address", hex(at));
		json.addProperty("op", normalizedOperation(mnemonic, callee));
		if (operation.getOutput() != null) {
			json.addProperty("result", varnodeName(operation.getOutput()));
		}
		JsonArray inputs = new JsonArray();
		JsonArray constants = new JsonArray();
		for (int index = inputStart; index < operation.getNumInputs(); index++) {
			if (inputs.size() >= 32) break;
			Varnode input = operation.getInput(index);
			inputs.add(varnodeName(input));
			if (input.isConstant() && constants.size() < 16) constants.add(input.getOffset());
		}
		json.add("inputs", inputs);
		json.add("constants", constants);
		if (callee != null) json.addProperty("target", callee);
		if (operation.getOutput() != null) {
			json.addProperty("width", Math.max(1, operation.getOutput().getSize() * 8));
		}
		JsonArray tags = new JsonArray();
		if (mnemonic.equals("PTRADD") || mnemonic.equals("PTRSUB")) {
			tags.add("pointer_arithmetic");
		}
		appendDirectCalleeAddressTag(tags, operation, mnemonic);
		appendControlFlowTags(tags, operation, mnemonic);
		if (isArgumentPreservingStackProbe(operation, mnemonic)) {
			tags.add("abi:argument_preserving_stack_probe");
		}
		if (operation.getOutput() != null) appendInputSourceTags(tags, callee);
		appendRangeReaderTags(tags, operation, callee, inputStart);
		json.add("tags", sorted(tags));
		json.addProperty("text", truncate(mnemonic + " " + operation.toString(), 1900));
		return json;
	}

	private boolean isArgumentPreservingStackProbe(PcodeOp operation, String mnemonic) {
		if (!mnemonic.equals("CALLIND")) return false;
		Address address = operation.getSeqnum().getTarget();
		Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
		if (function == null) return false;
		long delta = address.getOffset() - function.getEntryPoint().getOffset();
		if (delta < 0 || delta > 0x40) return false;

		Instruction call = currentProgram.getListing().getInstructionAt(address);
		if (!machineInstruction(call, "BLRAA", "x16", "x17")) return false;
		Instruction load = call.getPrevious();
		if (!machineInstruction(load, "LDR", "x16", "[x17]")) return false;
		Instruction add = load.getPrevious();
		if (!machineInstruction(add, "ADD", "x17", "x17")) return false;
		Instruction page = add.getPrevious();
		if (!machineInstruction(page, "ADRP", "x17")) return false;
		Instruction size = page.getPrevious();
		if (!(machineInstruction(size, "MOV", "w9") ||
				machineInstruction(size, "MOVZ", "w9"))) return false;
		String frameSize = operand(size, 1);
		if (!frameSize.startsWith("#")) return false;
		Instruction allocate = call.getNext();
		return machineInstruction(allocate, "SUB", "sp", "sp");
	}

	private boolean machineInstruction(Instruction instruction, String mnemonic,
			String... operands) {
		if (instruction == null ||
				!instruction.getMnemonicString().equalsIgnoreCase(mnemonic) ||
				instruction.getNumOperands() < operands.length) return false;
		for (int index = 0; index < operands.length; index++) {
			if (!operand(instruction, index).equals(operands[index])) return false;
		}
		return true;
	}

	private String operand(Instruction instruction, int index) {
		return instruction.getDefaultOperandRepresentation(index)
			.toLowerCase(Locale.ROOT).replace(" ", "");
	}

	private void appendDirectCalleeAddressTag(JsonArray tags, PcodeOp operation,
			String mnemonic) {
		if (!mnemonic.equals("CALL") || operation.getNumInputs() == 0) return;
		Address target = operation.getInput(0).getAddress();
		if (target == null || !target.isMemoryAddress()) return;
		tags.add("callee_address:" + Long.toUnsignedString(target.getOffset(), 16));
	}

	private void appendControlFlowTags(JsonArray tags, PcodeOp operation, String mnemonic) {
		String comparison = switch (mnemonic) {
			case "INT_EQUAL" -> "comparison:equal";
			case "INT_NOTEQUAL" -> "comparison:not_equal";
			case "INT_LESS" -> "comparison:unsigned_less";
			case "INT_LESSEQUAL" -> "comparison:unsigned_less_equal";
			case "INT_SLESS" -> "comparison:signed_less";
			case "INT_SLESSEQUAL" -> "comparison:signed_less_equal";
			default -> null;
		};
		if (comparison != null) tags.add(comparison);
		if (!mnemonic.equals("CBRANCH")) return;
		tags.add("conditional_branch");
		if (operation.getNumInputs() == 0 || operation.getInput(0).getAddress() == null) return;
		tags.add("branch_target:" + Long.toUnsignedString(
			operation.getInput(0).getAddress().getOffset(), 16));
	}

	private void appendInputSourceTags(JsonArray tags, String callee) {
		String canonical = callee == null ? "" :
			callee.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
		if (canonical.endsWith("cfdatagetlength")) {
			tags.add("input_length");
			tags.add("source_api:cf_data_length");
		}
		else if (canonical.endsWith("cgdataprovidergetsize") ||
				canonical.endsWith("cgimageprovidergetsize")) {
			tags.add("input_length");
			tags.add("source_api:image_provider_length");
		}
		else if (canonical.endsWith("cfdatagetbyteptr")) {
			tags.add("input_data");
			tags.add("source_api:cf_data_bytes");
		}
		else if (canonical.endsWith("cgdataprovidergetbytepointer")) {
			tags.add("input_data");
			tags.add("source_api:data_provider_bytes");
		}
	}

	private void appendRangeReaderTags(JsonArray tags, PcodeOp operation,
			String callee, int inputStart) {
		if (callee == null) return;
		String canonical = callee.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
		if (!RANGE_READER_IDENTITIES.contains(canonical)) return;
		int argumentCount = operation.getNumInputs() - inputStart;
		int bufferIndex;
		int offsetIndex;
		int lengthIndex;
		if (argumentCount >= 4) {
			bufferIndex = 1;
			offsetIndex = 2;
			lengthIndex = 3;
		}
		else if (argumentCount == 3) {
			bufferIndex = 0;
			offsetIndex = 1;
			lengthIndex = 2;
		}
		else {
			return;
		}
		tags.add("read_session_input");
		tags.add("input_buffer_operand:" + bufferIndex);
		tags.add("scalar_role:offset:" + offsetIndex);
		tags.add("scalar_role:requested_length:" + lengthIndex);
	}

	private JsonObject parameterInstruction(Function function, Parameter parameter, long at) {
		JsonObject json = new JsonObject();
		String name = parameterName(parameter);
		String lowered = (name + " " + parameter.getDataType().getDisplayName()).toLowerCase(Locale.ROOT);
		json.addProperty("address", hex(at));
		json.addProperty("op", "param");
		json.addProperty("result", name);
		json.add("inputs", new JsonArray());
		JsonArray tags = new JsonArray();
		if (lowered.matches(".*(data|buffer|bytes|src|input|provider|pointer|ptr).*")) {
			tags.add("input_data");
		}
		if (lowered.matches(".*(length|size|count|bytes|capacity).*")) {
			tags.add("input_length");
		}
		if (lowered.matches(".*(offset|index|position).*")) {
			tags.add("input_offset");
		}
		if (parserScore(function.getName()) > 0) tags.add("decoder_entry");
		json.add("tags", sorted(tags));
		json.addProperty("text", name + " = parameter");
		return json;
	}

	private JsonObject placeholderBlock(long start, long end) {
		JsonObject block = new JsonObject();
		block.addProperty("name", blockName(0, start));
		block.addProperty("start", hex(start));
		block.addProperty("size", Math.max(1L, end - start + 1L));
		block.add("successors", new JsonArray());
		JsonArray instructions = new JsonArray();
		instructions.add(placeholderInstruction(start));
		block.add("instructions", instructions);
		return block;
	}

	private JsonObject placeholderInstruction(long at) {
		JsonObject instruction = new JsonObject();
		instruction.addProperty("address", hex(at));
		instruction.addProperty("op", "unknown");
		instruction.add("inputs", new JsonArray());
		instruction.addProperty("text", "decompiler did not produce bounded p-code");
		return instruction;
	}

	private Census census(int maximumStrings) throws Exception {
		List<CoverageRow> rows = new ArrayList<>();
		Map<Long, CoverageRow> byEntry = new TreeMap<>();
		FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
		while (iterator.hasNext()) {
			Function function = iterator.next();
			if (function.isExternal() || function.isThunk()) continue;
			CoverageRow row = new CoverageRow(function);
			rows.add(row);
			byEntry.put(row.entry(), row);
		}
		rows.sort(Comparator.comparingLong(CoverageRow::entry));

		for (CoverageRow row : rows) {
			monitor.checkCancelled();
			List<Function> called = new ArrayList<>(row.function.getCalledFunctions(monitor));
			called.removeIf(function -> function.isExternal() || function.isThunk() ||
				!byEntry.containsKey(function.getEntryPoint().getOffset()));
			called.sort(Comparator.comparingLong(
				function -> function.getEntryPoint().getOffset()));
			for (Function callee : called.subList(0, Math.min(MAX_CENSUS_EDGES, called.size()))) {
				long target = callee.getEntryPoint().getOffset();
				row.callees.add(target);
				byEntry.get(target).callers.add(row.entry());
			}
		}
		for (CoverageRow row : rows) {
			while (row.callers.size() > MAX_CENSUS_EDGES) row.callers.pollLast();
		}

		JsonArray strings = new JsonArray();
		Iterator<Data> dataIterator = currentProgram.getListing().getDefinedData(true);
		while (dataIterator.hasNext() && strings.size() < maximumStrings) {
			monitor.checkCancelled();
			Data data = dataIterator.next();
			Object value = data.getValue();
			if (!(value instanceof String) || ((String) value).isBlank()) continue;
			String text = truncate((String) value, 3900);
			JsonObject item = new JsonObject();
			item.addProperty("address", address(data.getAddress()));
			item.addProperty("value", text);
			TreeSet<Long> references = new TreeSet<>();
			for (Reference reference :
					currentProgram.getReferenceManager().getReferencesTo(data.getAddress())) {
				long from = reference.getFromAddress().getOffset();
				references.add(from);
				Function containing = currentProgram.getFunctionManager()
					.getFunctionContaining(reference.getFromAddress());
				if (containing == null) continue;
				CoverageRow row = byEntry.get(containing.getEntryPoint().getOffset());
				if (row != null && row.directStrings.size() < MAX_DIRECT_STRINGS) {
					row.directStrings.add(truncate(text, 500));
				}
				if (references.size() >= 1024) break;
			}
			JsonArray referenceJson = new JsonArray();
			for (long reference : references) referenceJson.add(hex(reference));
			item.add("references", referenceJson);
			strings.add(item);
		}
		return new Census(rows, strings);
	}

	private List<CoverageRow> selectFunctions(List<CoverageRow> rows, int maximum,
			int coverageDepth, int maximumEvidence) {
		Map<Long, CoverageRow> byEntry = new TreeMap<>();
		for (CoverageRow row : rows) byEntry.put(row.entry(), row);

		List<CoverageRow> frontier = new ArrayList<>();
		List<CoverageRow> rangeReaderBoundaries = new ArrayList<>();
		TreeSet<String> parserOwners = new TreeSet<>();
		for (CoverageRow row : rows) {
			TreeSet<String> directReasons = new TreeSet<>();
			boolean hasNameAction = false;
			boolean isRangeReader = RANGE_READER_IDENTITIES.contains(
				row.function.getName().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", ""));
			if (isRangeReader) {
				directReasons.add("range_reader_boundary");
				rangeReaderBoundaries.add(row);
			}
			for (String marker : PARSER_MARKERS) {
				if (hasNameMarker(row.function.getName(), marker)) {
					directReasons.add("name_marker:" + marker);
					hasNameAction |= NAME_ACTION_MARKERS.contains(marker);
				}
			}
			boolean hasStringEvidence = false;
			for (String value : row.directStrings) {
				String lowered = value.toLowerCase(Locale.ROOT);
				for (String marker : EVIDENCE_STRING_MARKERS) {
					if (lowered.contains(marker)) {
						directReasons.add("string_marker:" + marker);
						hasStringEvidence = true;
					}
				}
			}
			if (hasNameAction || hasStringEvidence || isRangeReader) {
				row.selected = true;
				row.selectionTier = "mandatory";
				row.selectionReasons.addAll(directReasons);
				frontier.add(row);
				String owner = functionOwner(row.function.getName(true));
				if (owner != null) parserOwners.add(owner);
			}
		}
		for (CoverageRow row : rows) {
			String owner = functionOwner(row.function.getName(true));
			if (owner == null || !parserOwners.contains(owner) ||
					!isOwnerConstructor(row.function, owner)) continue;
			row.selectionReasons.add("parser_owner_constructor:owner=" + owner);
			if (row.selected) continue;
			row.selected = true;
			row.selectionTier = "mandatory";
			frontier.add(row);
		}
		for (CoverageRow boundary : rangeReaderBoundaries) {
			for (long target : boundary.callees) {
				CoverageRow callee = byEntry.get(target);
				if (callee == null) continue;
				if (callee.callers.size() != 1 || !callee.callers.contains(boundary.entry())) {
					continue;
				}
				callee.selectionReasons.add(
					"range_reader_exclusive_callee:seed=" + hex(boundary.entry()));
				if (callee.selected) continue;
				callee.selected = true;
				callee.selectionTier = "mandatory";
				frontier.add(callee);
			}
		}
		frontier.sort(Comparator.comparingLong(CoverageRow::entry));
		if (frontier.size() > maximumEvidence) {
			throw new IllegalStateException(
				"mandatory evidence functions exceed max-evidence-functions");
		}

		int evidenceCount = frontier.size();
		int evidenceBudget = Math.max(
			frontier.size(), Math.min(maximum, maximumEvidence));
		boolean neighborhoodTruncated = false;
		for (int depth = 1; depth <= coverageDepth && !frontier.isEmpty(); depth++) {
			TreeMap<Long, TreeSet<String>> nextReasons = new TreeMap<>();
			for (CoverageRow source : frontier) {
				for (long caller : source.callers) {
					nextReasons.computeIfAbsent(caller, ignored -> new TreeSet<>()).add(
						"callgraph:caller:depth=" + depth + ":seed=" + hex(source.entry()));
				}
				for (long callee : source.callees) {
					nextReasons.computeIfAbsent(callee, ignored -> new TreeSet<>()).add(
						"callgraph:callee:depth=" + depth + ":seed=" + hex(source.entry()));
				}
			}
			List<CoverageRow> next = new ArrayList<>();
			for (Map.Entry<Long, TreeSet<String>> candidate : nextReasons.entrySet()) {
				CoverageRow row = byEntry.get(candidate.getKey());
				if (row == null || row.selected) continue;
				if (evidenceCount >= evidenceBudget) {
					neighborhoodTruncated = true;
					continue;
				}
				row.selected = true;
				row.selectionTier = "neighborhood";
				row.selectionReasons.addAll(candidate.getValue());
				evidenceCount++;
				next.add(row);
			}
			frontier = next;
		}

		List<CoverageRow> fallback = new ArrayList<>(rows);
		fallback.sort(Comparator
			.comparingInt((CoverageRow row) -> -parserScore(row.function.getName()))
			.thenComparingLong(CoverageRow::entry));
		int selectedCount = evidenceCount;
		for (CoverageRow row : fallback) {
			if (row.selected || selectedCount >= maximum) continue;
			row.selected = true;
			row.selectionTier = "fallback";
			row.selectionReasons.add("parser_score_fallback:" +
				parserScore(row.function.getName()));
			selectedCount++;
		}
		for (CoverageRow row : rows) {
			if (!row.selected) {
				row.omissionReason = neighborhoodTruncated && evidenceCount >= evidenceBudget ?
					"evidence_neighborhood_or_fallback_cap_reached" :
					"fallback_cap_reached";
			}
		}

		List<CoverageRow> selected = new ArrayList<>();
		for (CoverageRow row : rows) if (row.selected) selected.add(row);
		selected.sort(Comparator
			.comparingInt((CoverageRow row) -> tierOrder(row.selectionTier))
			.thenComparingLong(CoverageRow::entry));
		return selected;
	}

	private JsonObject coverageManifest(List<CoverageRow> rows, List<CoverageRow> selected,
			String snapshot, int maximum, int depth, int maximumEvidence) {
		JsonObject manifest = new JsonObject();
		manifest.addProperty("schema_version", "ghidra-function-coverage-v1");
		manifest.addProperty("snapshot_sha256", snapshot);
		manifest.addProperty("maximum_functions", maximum);
		manifest.addProperty("maximum_evidence_functions", maximumEvidence);
		manifest.addProperty("callgraph_depth", depth);
		JsonArray warnings = new JsonArray();
		if (selected.size() < rows.size()) warnings.add("function_export_cap_saturated");
		manifest.add("warnings", warnings);
		JsonArray functions = new JsonArray();
		for (CoverageRow row : rows) functions.add(row.toJson());
		manifest.add("functions", functions);
		return manifest;
	}

	private JsonArray virtualMethodReferences(List<CoverageRow> selected) {
		TreeMap<Long, VtableSymbol> tables = new TreeMap<>();
		SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();
			String qualified = symbol.getName(true);
			String owner = vtableOwner(qualified);
			if (owner != null && symbol.getAddress() != null && symbol.getAddress().isMemoryAddress()) {
				tables.putIfAbsent(
					symbol.getAddress().getOffset(),
					new VtableSymbol(owner, qualified, symbol.getAddress().getOffset()));
			}
		}
		int pointerSize = currentProgram.getDefaultPointerSize();
		if (pointerSize != 8) return new JsonArray();
		TreeMap<String, JsonObject> ordered = new TreeMap<>();
		for (CoverageRow row : selected) {
			Function function = row.function;
			String owner = functionOwner(function.getName(true));
			if (owner == null) continue;
			for (Reference reference :
					currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())) {
				if (!reference.getReferenceType().isData()) continue;
				Address fromAddress = reference.getFromAddress();
				if (fromAddress == null || !fromAddress.isMemoryAddress()) continue;
				long from = fromAddress.getOffset();
				Map.Entry<Long, VtableSymbol> candidate = tables.floorEntry(from);
				if (candidate == null || !candidate.getValue().owner.equals(owner)) continue;
				VtableSymbol table = candidate.getValue();
				long addressPoint = table.address + 2L * pointerSize;
				long slotOffset = from - addressPoint;
				if (slotOffset < 0 || slotOffset > 64L * 1024L ||
						slotOffset % pointerSize != 0) continue;
				JsonObject json = new JsonObject();
				json.addProperty("owner", owner);
				json.addProperty("vtable_symbol", table.symbol);
				json.addProperty("vtable_address", hex(table.address));
				json.addProperty("address_point", hex(addressPoint));
				json.addProperty("slot_offset", slotOffset);
				json.addProperty("reference_address", hex(from));
				json.addProperty("target_entry", address(function.getEntryPoint()));
				String key = hex(function.getEntryPoint().getOffset()) + ":" +
					hex(slotOffset) + ":" + hex(table.address) + ":" + hex(from);
				ordered.putIfAbsent(key, json);
			}
		}
		JsonArray references = new JsonArray();
		for (JsonObject reference : ordered.values()) references.add(reference);
		return references;
	}

	private String vtableOwner(String qualified) {
		String suffix = "::vtable";
		return qualified.endsWith(suffix) && qualified.length() > suffix.length() ?
			qualified.substring(0, qualified.length() - suffix.length()) : null;
	}

	private String functionOwner(String qualified) {
		int separator = qualified.lastIndexOf("::");
		return separator > 0 ? qualified.substring(0, separator) : null;
	}

	private boolean isOwnerConstructor(Function function, String owner) {
		int separator = owner.lastIndexOf("::");
		String leaf = separator >= 0 ? owner.substring(separator + 2) : owner;
		return function.getName().equals(leaf);
	}

	private int parserScore(String name) {
		String lowered = name.toLowerCase(Locale.ROOT);
		int score = 0;
		for (String marker : PARSER_MARKERS) {
			if (lowered.contains(marker)) score += 10;
		}
		return score;
	}

	private boolean hasNameMarker(String name, String marker) {
		String lowered = name.toLowerCase(Locale.ROOT);
		if (!marker.equals("read") && !marker.equals("rle")) {
			return lowered.contains(marker);
		}
		return lowered.matches(".*(?:^|[^a-z0-9])" + marker +
			"(?:[^a-z0-9]|$).*");
	}

	private JsonArray imports() {
		Set<String> names = new HashSet<>();
		FunctionIterator iterator = currentProgram.getFunctionManager().getExternalFunctions();
		while (iterator.hasNext()) names.add(iterator.next().getName());
		String[] ordered = names.toArray(new String[0]);
		Arrays.sort(ordered);
		JsonArray json = new JsonArray();
		for (String name : ordered) json.add(name);
		return json;
	}

	private String resolveCallee(PcodeOp operation) {
		if (operation.getNumInputs() == 0) return "indirect_call";
		Varnode target = operation.getInput(0);
		Address targetAddress = target.getAddress();
		Function function = currentProgram.getFunctionManager().getFunctionAt(targetAddress);
		if (function != null) return function.getName();
		if (targetAddress != null) {
			Function containing = currentProgram.getFunctionManager().getFunctionContaining(targetAddress);
			if (containing != null) return containing.getName();
			if (currentProgram.getSymbolTable().getPrimarySymbol(targetAddress) != null) {
				return currentProgram.getSymbolTable().getPrimarySymbol(targetAddress).getName();
			}
			return address(targetAddress);
		}
		return "indirect_call";
	}

	private String normalizedOperation(String mnemonic, String callee) {
		if (mnemonic.equals("CALL") || mnemonic.equals("CALLIND")) {
			String lowered = callee == null ? "" : callee.toLowerCase(Locale.ROOT);
			if (lowered.contains("memcpy") || lowered.contains("memmove") || lowered.contains("bcopy")) return "copy";
			if (lowered.contains("malloc") || lowered.contains("calloc") || lowered.contains("realloc") || lowered.contains("cfallocatorallocate")) return "alloc";
			if (lowered.equals("free") || lowered.contains("operator_delete")) return "free";
			String canonical = lowered.replaceAll("[^a-z0-9]", "");
			if (canonical.contains("byteswap") || canonical.contains("swapint") ||
				canonical.equals("bswap16") || canonical.equals("bswap32") ||
				canonical.equals("bswap64")) return "byte_swap";
			return "call";
		}
		return switch (mnemonic) {
			case "COPY" -> "assign";
			case "MULTIEQUAL" -> "phi";
			case "INT_ADD", "PTRADD" -> "int_add";
			case "INT_SUB", "PTRSUB" -> "int_sub";
			case "INT_MULT" -> "int_mult";
			case "INT_LEFT" -> "int_left";
			case "INT_RIGHT", "INT_SRIGHT" -> "int_right";
			case "INT_AND" -> "and";
			case "INT_OR" -> "int_or";
			case "INT_BSWAP" -> "byte_swap";
			case "BOOL_AND" -> "boolean_and";
			case "BOOL_OR" -> "boolean_or";
			case "BOOL_XOR" -> "boolean_xor";
			case "BOOL_NEGATE" -> "boolean_not";
			case "INT_ZEXT", "INT_SEXT", "CAST", "SUBPIECE", "PIECE" -> "cast";
			case "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL" -> "cmp";
			case "BRANCH", "CBRANCH", "BRANCHIND" -> "branch";
			case "LOAD" -> "load";
			case "STORE" -> "store";
			case "RETURN" -> "ret";
			default -> mnemonic.toLowerCase(Locale.ROOT);
		};
	}

	private String varnodeName(Varnode node) {
		if (node.isConstant()) return "const_" + Long.toUnsignedString(node.getOffset(), 16);
		HighVariable high = node.getHigh();
		if (high != null && high.getName() != null && !high.getName().isBlank() &&
				!high.getName().equalsIgnoreCase("UNNAMED")) {
			// Ghidra display names such as uVar14 can be reused by several SSA
			// definitions. Parameters have no defining p-code operation and must
			// retain their declared name so the synthetic PARAMETER record joins
			// with its uses. Defined locals receive a deterministic storage/def
			// suffix so loop and PHI flows cannot collapse by display name alone.
			if (node.getDef() == null) return truncate(high.getName(), 150);
			return truncate(high.getName(), 72) + "_" + varnodeIdentity(node);
		}
		return truncate("v_" + varnodeIdentity(node), 150);
	}

	private String varnodeIdentity(Varnode node) {
		String space = node.getAddress() == null ? "none" :
			node.getAddress().getAddressSpace().getName().replaceAll("[^A-Za-z0-9_]", "_");
		String identity = space + "_" + Long.toUnsignedString(node.getOffset(), 16) +
			"_" + node.getSize();
		if (node.getDef() != null) {
			identity += "_" + Long.toUnsignedString(
				node.getDef().getSeqnum().getTarget().getOffset(), 16) + "_" +
				node.getDef().getSeqnum().getTime();
		}
		return identity;
	}

	private String parameterName(Parameter parameter) {
		String name = parameter.getName();
		return name == null || name.isBlank() ? "param_" + parameter.getOrdinal() : truncate(name, 150);
	}

	private JsonArray sorted(JsonArray array) {
		List<String> values = new ArrayList<>();
		array.forEach(item -> values.add(item.getAsString()));
		values.sort(String::compareTo);
		JsonArray sorted = new JsonArray();
		values.stream().distinct().forEach(sorted::add);
		return sorted;
	}

	private String architecture() {
		String processor = currentProgram.getLanguage().getProcessor().toString().toLowerCase(Locale.ROOT);
		if (processor.contains("aarch64") || processor.contains("arm")) return "arm64";
		if (processor.contains("x86")) return "x86_64";
		throw new IllegalStateException("unsupported ImageIO architecture: " + processor);
	}

	private static int boundedInt(String value, String label, int minimum, int maximum) {
		int parsed = Integer.parseInt(value);
		if (parsed < minimum || parsed > maximum) throw new IllegalArgumentException(label + " is out of range");
		return parsed;
	}

	private static int tierOrder(String tier) {
		if ("mandatory".equals(tier)) return 0;
		if ("neighborhood".equals(tier)) return 1;
		return 2;
	}

	private static String blockName(int ordinal, long start) {
		return "bb_" + ordinal + "_" + Long.toUnsignedString(start, 16);
	}

	private static String address(Address value) {
		return hex(value.getOffset());
	}

	private static String hex(long value) {
		return "0x" + Long.toUnsignedString(value, 16);
	}

	private static String truncate(String value, int maximum) {
		return value.length() <= maximum ? value : value.substring(0, maximum);
	}

	private static class Census {
		final List<CoverageRow> rows;
		final JsonArray strings;

		Census(List<CoverageRow> rows, JsonArray strings) {
			this.rows = rows;
			this.strings = strings;
		}
	}

	private static class CoverageRow {
		final Function function;
		final TreeSet<String> directStrings = new TreeSet<>();
		final TreeSet<Long> callers = new TreeSet<>();
		final TreeSet<Long> callees = new TreeSet<>();
		final TreeSet<String> selectionReasons = new TreeSet<>();
		boolean selected;
		String selectionTier;
		String omissionReason;

		CoverageRow(Function function) {
			this.function = function;
		}

		long entry() {
			return function.getEntryPoint().getOffset();
		}

		JsonObject toJson() {
			long start = entry();
			long end = Math.max(start, function.getBody().getMaxAddress().getOffset());
			JsonObject json = new JsonObject();
			json.addProperty("entry", hex(start));
			json.addProperty("size", Math.max(1L, end - start + 1L));
			json.addProperty("name", function.getName());
			JsonArray strings = new JsonArray();
			for (String value : directStrings) strings.add(value);
			json.add("direct_strings", strings);
			JsonArray callerJson = new JsonArray();
			for (long caller : callers) callerJson.add(hex(caller));
			json.add("callers", callerJson);
			JsonArray calleeJson = new JsonArray();
			for (long callee : callees) calleeJson.add(hex(callee));
			json.add("callees", calleeJson);
			json.addProperty("selected", selected);
			if (selectionTier != null) json.addProperty("selection_tier", selectionTier);
			JsonArray reasons = new JsonArray();
			for (String reason : selectionReasons) reasons.add(reason);
			json.add("selection_reasons", reasons);
			if (omissionReason != null) json.addProperty("omission_reason", omissionReason);
			return json;
		}
	}

	private static class VtableSymbol {
		final String owner;
		final String symbol;
		final long address;

		VtableSymbol(String owner, String symbol, long address) {
			this.owner = owner;
			this.symbol = symbol;
			this.address = address;
		}
	}
}
