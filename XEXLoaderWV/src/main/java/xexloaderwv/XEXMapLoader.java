package xexloaderwv;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public final class XEXMapLoader {
	private static final Pattern BASE = Pattern.compile("^\\s*Preferred load address is\\s+([0-9a-f]{1,8})\\s*$",
			Pattern.CASE_INSENSITIVE);
	private static final Pattern TABLE = Pattern
			.compile("^\\s*(?:Address\\s+)?(Publics by Value|Static symbols)(?:\\s+.*)?$", Pattern.CASE_INSENSITIVE);
	private static final Pattern ROW = Pattern
			.compile("^\\s*([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,8})\\s+(\\S+)\\s+([0-9a-fA-F]{1,8})(?:\\s+(.*?))?\\s*$");
	private static final Pattern ADDRESS_ROW = Pattern.compile("^\\s*[0-9a-fA-F]+:.*$");

	public record MapSymbol(int segment, long offset, String name, long address, boolean function, boolean isStatic,
			int line) {
	}

	public record MapFile(long preferredBase, List<MapSymbol> symbols) {
	}

	private XEXMapLoader() {
	}

	public static MapFile read(Path path, BooleanSupplier cancelled) throws IOException {
		List<MapSymbol> symbols = new ArrayList<>();
		long base = -1;
		boolean inTable = false;
		boolean isStatic = false;
		boolean sawTable = false;
		int lineNumber = 0;
		try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.ISO_8859_1)) {
			String line;
			while ((line = reader.readLine()) != null) {
				if (cancelled.getAsBoolean())
					throw new InterruptedIOException("MAP reading cancelled");
				lineNumber++;
				var baseMatch = BASE.matcher(line);
				if (baseMatch.matches()) {
					long value = Long.parseUnsignedLong(baseMatch.group(1), 16);
					if (base != -1 && base != value)
						throw new IOException("Conflicting preferred load addresses at line " + lineNumber);
					base = value;
					continue;
				}
				var tableMatch = TABLE.matcher(line);
				if (tableMatch.matches()) {
					inTable = true;
					sawTable = true;
					isStatic = tableMatch.group(1).equalsIgnoreCase("Static symbols");
					continue;
				}
				if (!inTable || line.isBlank())
					continue;
				var row = ROW.matcher(line);
				if (!row.matches()) {
					if (ADDRESS_ROW.matcher(line).matches())
						throw new IOException("Invalid MAP symbol row at line " + lineNumber);
					if (line.stripLeading().startsWith("Address"))
						continue;
					inTable = false;
					continue;
				}
				String tail = row.group(5);
				boolean function = false;
				if (tail != null) {
					for (String token : tail.strip().split("\\s+")) {
						if (token.equalsIgnoreCase("f"))
							function = true;
						else if (!token.equalsIgnoreCase("i"))
							break;
					}
				}
				symbols.add(new MapSymbol(Integer.parseUnsignedInt(row.group(1), 16),
						Long.parseUnsignedLong(row.group(2), 16), row.group(3),
						Long.parseUnsignedLong(row.group(4), 16), function, isStatic, lineNumber));
			}
		}
		if (base == -1 || !sawTable || symbols.isEmpty())
			throw new IOException("MAP has no preferred load address or supported symbol rows");
		return new MapFile(base, List.copyOf(symbols));
	}

	public static void apply(Path path, Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {
		monitor.checkCancelled();
		long start = System.nanoTime();
		monitor.setMessage("Reading MAP file");
		MapFile map;
		try {
			map = read(path, monitor::isCancelled);
		} catch (InterruptedIOException ex) {
			monitor.checkCancelled();
			throw ex;
		}
		monitor.checkCancelled();
		long imageBase = program.getImageBase().getOffset();
		log.appendMsg("MAP: " + path.getFileName());
		log.appendMsg(String.format("MAP base: %08X, program base: %08X", map.preferredBase(), imageBase));
		if (map.preferredBase() != imageBase)
			throw new IOException("Image bases differ; no MAP symbols imported");
		var space = program.getAddressFactory().getDefaultAddressSpace();
		var memory = program.getMemory();
		var table = program.getSymbolTable();
		int publicRows = 0;
		int staticRows = 0;
		int functionRows = 0;
		int unmapped = 0;
		int invalid = 0;
		int imported = 0;
		int existing = 0;
		int rejected = 0;
		monitor.initialize(map.symbols().size());
		monitor.setMessage("Importing MAP symbols");
		for (var row : map.symbols()) {
			monitor.checkCancelled();
			if (row.isStatic())
				staticRows++;
			else
				publicRows++;
			if (row.function())
				functionRows++;
			var address = space.getAddress(row.address());
			if (memory.getBlock(address) == null) {
				unmapped++;
				if (unmapped <= 5)
					log.appendMsg("MAP unmapped row " + row.line() + " at " + address);
			} else if (row.name().chars().anyMatch(Character::isISOControl)) {
				invalid++;
				if (invalid <= 5)
					log.appendMsg("MAP control-character name at row " + row.line());
			} else if (table.getGlobalSymbol(row.name(), address) != null) {
				existing++;
			} else {
				try {
					table.createLabel(address, row.name(), SourceType.IMPORTED);
					imported++;
				} catch (InvalidInputException ex) {
					rejected++;
					if (rejected <= 5)
						log.appendMsg("MAP rejected row " + row.line() + ": " + ex.getMessage());
				}
			}
			monitor.incrementProgress(1);
		}
		monitor.checkCancelled();
		log.appendMsg("MAP public rows: " + publicRows);
		log.appendMsg("MAP static rows: " + staticRows);
		log.appendMsg("MAP function-flagged rows: " + functionRows);
		log.appendMsg("MAP imported names: " + imported);
		log.appendMsg("MAP existing names: " + existing);
		log.appendMsg("MAP unmapped rows: " + unmapped);
		log.appendMsg("MAP control-character name rows: " + invalid);
		log.appendMsg("MAP skipped rows: " + (unmapped + invalid));
		log.appendMsg("MAP rejected names: " + rejected);
		log.appendMsg(String.format("MAP elapsed: %.2f seconds", (System.nanoTime() - start) / 1e9));
	}
}
