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
import java.util.Set;

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
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;

public class ExportImageIOIR extends GhidraScript {
	private static final int MAX_PSEUDOCODE_CHARS = 240000;
	private static final Set<String> PARSER_MARKERS = Set.of(
		"decode", "decoder", "parse", "parser", "reader", "image", "tiff", "dng",
		"jpeg", "jp2", "png", "gif", "heif", "webp", "dicom");

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 6) {
			throw new IllegalArgumentException(
				"usage: ExportImageIOIR.java <output> <snapshot-sha256> <image-uuid> " +
				"<max-functions> <max-ops-per-function> <decompile-seconds>");
		}
		File output = new File(args[0]).getCanonicalFile();
		String snapshot = args[1];
		String imageUuid = args[2].toUpperCase(Locale.ROOT);
		int maxFunctions = boundedInt(args[3], "max-functions", 1, 10000);
		int maxOps = boundedInt(args[4], "max-ops-per-function", 1, 9990);
		int decompileSeconds = boundedInt(args[5], "decompile-seconds", 1, 120);
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
		root.addProperty("schema_version", "ghidra-imageio-export-v1");
		root.addProperty("decompiler_version", Application.getApplicationVersion());
		root.addProperty("snapshot_sha256", snapshot);
		JsonObject image = new JsonObject();
		image.addProperty("name", currentProgram.getName());
		image.addProperty("uuid", imageUuid);
		image.addProperty("architecture", architecture());
		image.addProperty("base_address", address(currentProgram.getImageBase()));
		root.add("image", image);
		root.add("imports", imports());
		root.add("strings", strings(20000));

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
			List<Function> selected = selectFunctions(maxFunctions);
			monitor.initialize(selected.size(), "Exporting bounded ImageIO IR");
			for (Function function : selected) {
				monitor.checkCancelled();
				functions.add(exportFunction(decompiler, function, maxOps, decompileSeconds));
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
			Varnode input = operation.getInput(index);
			inputs.add(varnodeName(input));
			if (input.isConstant()) constants.add(input.getOffset());
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
		appendControlFlowTags(tags, operation, mnemonic);
		if (operation.getOutput() != null) appendInputSourceTags(tags, callee);
		json.add("tags", sorted(tags));
		json.addProperty("text", truncate(mnemonic + " " + operation.toString(), 1900));
		return json;
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

	private List<Function> selectFunctions(int maximum) {
		List<Function> functions = new ArrayList<>();
		FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
		while (iterator.hasNext()) {
			Function function = iterator.next();
			if (!function.isExternal() && !function.isThunk()) functions.add(function);
		}
		functions.sort(Comparator
			.comparingInt((Function function) -> -parserScore(function.getName()))
			.thenComparingLong(function -> function.getEntryPoint().getOffset()));
		return new ArrayList<>(functions.subList(0, Math.min(maximum, functions.size())));
	}

	private int parserScore(String name) {
		String lowered = name.toLowerCase(Locale.ROOT);
		int score = 0;
		for (String marker : PARSER_MARKERS) {
			if (lowered.contains(marker)) score += 10;
		}
		return score;
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

	private JsonArray strings(int maximum) {
		JsonArray result = new JsonArray();
		Iterator<Data> iterator = currentProgram.getListing().getDefinedData(true);
		while (iterator.hasNext() && result.size() < maximum) {
			Data data = iterator.next();
			Object value = data.getValue();
			if (!(value instanceof String) || ((String) value).isBlank()) continue;
			JsonObject item = new JsonObject();
			item.addProperty("address", address(data.getAddress()));
			item.addProperty("value", truncate((String) value, 3900));
			JsonArray references = new JsonArray();
			for (Reference reference : currentProgram.getReferenceManager().getReferencesTo(data.getAddress())) {
				references.add(address(reference.getFromAddress()));
				if (references.size() >= 1024) break;
			}
			item.add("references", references);
			result.add(item);
		}
		return result;
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
			return "call";
		}
		return switch (mnemonic) {
			case "COPY" -> "assign";
			case "MULTIEQUAL" -> "phi";
			case "INT_ADD", "PTRADD" -> "int_add";
			case "INT_SUB", "PTRSUB" -> "int_sub";
			case "INT_MULT" -> "int_mult";
			case "INT_LEFT" -> "int_left";
			case "INT_AND" -> "and";
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
			return truncate(high.getName(), 150);
		}
		String space = node.getAddress() == null ? "none" :
			node.getAddress().getAddressSpace().getName().replaceAll("[^A-Za-z0-9_]", "_");
		String identity = "v_" + space + "_" + Long.toUnsignedString(node.getOffset(), 16) +
			"_" + node.getSize();
		if (node.getDef() != null) {
			identity += "_" + Long.toUnsignedString(
				node.getDef().getSeqnum().getTarget().getOffset(), 16) + "_" +
				node.getDef().getSeqnum().getTime();
		}
		return truncate(identity, 150);
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
}
