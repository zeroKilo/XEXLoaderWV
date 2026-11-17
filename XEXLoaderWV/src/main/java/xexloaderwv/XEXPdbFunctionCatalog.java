package xexloaderwv;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbNewDebugInfo;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordCategory;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractProcedureMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.BadMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMemberFunctionMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractProcedureMsType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class XEXPdbFunctionCatalog {
	private static final int S_LPROC32 = 0x110F;
	private static final int S_GPROC32 = 0x1110;

	public enum PrototypeKind {
		PROCEDURE, MEMBER_FUNCTION, UNSUPPORTED
	}

	public record FunctionEntry(int module, int stream, int recordOffset, int symbolKind, String name, int segment,
			long sectionOffset, long length, Address address, RecordNumber typeRecord, PrototypeKind prototypeKind,
			boolean exactFunctionEntry) {
	}

	private XEXPdbFunctionCatalog() {
	}

	public static List<FunctionEntry> collectVerified(AbstractPdb pdb, Program program, TaskMonitor monitor,
			MessageLog log) throws Exception {
		if (!(pdb.getDebugInfo() instanceof PdbNewDebugInfo dbi) || dbi.getDebugData() == null)
			throw new IOException("Missing supported DBI debug data");
		var debug = dbi.getDebugData();
		var sections = debug.getImageSectionHeaders();
		var omap = debug.getOmapFromSource();
		if (debug.getImageSectionHeadersOrig() != null || (omap != null && !omap.isEmpty()))
			throw new IOException("Unsupported procedure address remapping");
		if (sections == null || sections.isEmpty())
			throw new IOException("Missing PDB section headers");
		var tpi = pdb.getTypeProgramInterface();
		if (tpi == null)
			throw new IOException("Missing PDB type information");
		var records = dbi.getSymbolRecords();
		if (records == null)
			throw new IOException("Missing PDB symbol records");
		var memory = program.getMemory();
		var functions = program.getFunctionManager();
		var space = program.getAddressFactory().getDefaultAddressSpace();
		long base = program.getImageBase().getOffset();
		if (base < 0 || base > 0xFFFFFFFFL)
			throw new IOException("Invalid XEX image base");
		Map<Long, FunctionEntry> entries = new TreeMap<>();
		Set<Long> ambiguous = new HashSet<>();
		Map<Integer, PrototypeKind> typeKinds = new TreeMap<>();
		int globalCount = 0;
		int localCount = 0;
		int invalidCount = 0;
		int scannedModules = 0;
		long scannedRecords = 0;
		monitor.setMessage("Collecting PDB procedure records");
		monitor.initialize(dbi.getNumModules());
		for (int module = 1; module <= dbi.getNumModules(); module++) {
			monitor.checkCancelled();
			var info = dbi.getModuleInformation(module);
			int stream = info.getStreamNumberDebugInformation();
			int size = info.getSizeLocalSymbolsDebugInformation();
			monitor.incrementProgress(1);
			if (size == 0)
				continue;
			if (stream <= 0 || stream == 0xFFFF || size < 0)
				throw new IOException("Invalid module symbol stream: " + module);
			int offset = records.getCvSigLength(stream);
			if (offset < 0 || offset > size)
				throw new IOException("Invalid module symbol bounds: " + module);
			scannedModules++;
			while (offset < size) {
				monitor.checkCancelled();
				int recordOffset = offset;
				var item = records.getRandomAccessRecord(stream, offset);
				if (item == null || item.length() < 4 || item.length() > size - offset)
					throw new IOException("Invalid symbol record in module " + module + " at offset " + offset);
				offset += item.length();
				scannedRecords++;
				var raw = item.symbol();
				if (raw == null || raw instanceof BadMsSymbol)
					throw new IOException("Unusable symbol record in module " + module + " at offset " + recordOffset);
				int kind = raw.getPdbId();
				if (kind != S_GPROC32 && kind != S_LPROC32)
					continue;
				if (!(raw instanceof AbstractProcedureMsSymbol symbol))
					throw new IOException("Unexpected procedure symbol representation");
				if (kind == S_GPROC32)
					globalCount++;
				else
					localCount++;
				int segment = symbol.getSegment();
				long sectionOffset = symbol.getOffset();
				long length = symbol.getProcedureLength();
				if (segment < 1 || segment > sections.size() || sectionOffset < 0 || length <= 0 || (length & 3) != 0) {
					invalidCount++;
					continue;
				}
				var section = sections.get(segment - 1);
				long sectionSize = section.getUnionPAVS();
				long sectionStart = base + section.getVirtualAddress();
				long va = sectionStart + sectionOffset;
				long end = va + length - 1;
				if ((section.getCharacteristics() & 0x20000000L) == 0 || sectionOffset >= sectionSize
						|| length > sectionSize - sectionOffset || sectionStart < base || va < sectionStart || end < va
						|| end > 0xFFFFFFFFL || (va & 3) != 0) {
					invalidCount++;
					continue;
				}
				Address address = space.getAddress(va);
				var block = memory.getBlock(address);
				if (block == null || !block.isInitialized() || !block.isExecute()
						|| block.getStart().getOffset() != sectionStart || block.getSize() != sectionSize
						|| end > block.getEnd().getOffset()) {
					invalidCount++;
					continue;
				}
				RecordNumber typeRecord = symbol.getTypeRecordNumber();
				PrototypeKind prototypeKind = PrototypeKind.UNSUPPORTED;
				if (typeRecord != null && typeRecord.getCategory() == RecordCategory.TYPE) {
					int index = typeRecord.getNumber();
					if (index >= tpi.getTypeIndexMin() && index < tpi.getTypeIndexMaxExclusive()) {
						prototypeKind = typeKinds.computeIfAbsent(index, key -> {
							var type = tpi.getRandomAccessRecord(key);
							if (type instanceof AbstractProcedureMsType)
								return PrototypeKind.PROCEDURE;
							if (type instanceof AbstractMemberFunctionMsType)
								return PrototypeKind.MEMBER_FUNCTION;
							return PrototypeKind.UNSUPPORTED;
						});
					}
				}
				if (ambiguous.contains(va))
					continue;
				if (entries.containsKey(va)) {
					entries.remove(va);
					ambiguous.add(va);
					continue;
				}
				var entry = new FunctionEntry(module, stream, recordOffset, kind, symbol.getName(), segment,
						sectionOffset, length, address, typeRecord, prototypeKind,
						functions.getFunctionAt(address) != null);
				entries.put(va, entry);
			}
		}
		int procedureCount = 0;
		int memberCount = 0;
		int unsupportedCount = 0;
		int exactCount = 0;
		for (var entry : entries.values()) {
			monitor.checkCancelled();
			switch (entry.prototypeKind()) {
			case PROCEDURE:
				procedureCount++;
				break;
			case MEMBER_FUNCTION:
				memberCount++;
				break;
			case UNSUPPORTED:
				unsupportedCount++;
				break;
			}
			if (entry.exactFunctionEntry())
				exactCount++;
		}
		log.appendMsg("PDB modules with symbols: " + scannedModules);
		log.appendMsg("PDB module symbol records: " + scannedRecords);
		log.appendMsg("PDB global procedures: " + globalCount);
		log.appendMsg("PDB local procedures: " + localCount);
		log.appendMsg("PDB invalid procedure ranges: " + invalidCount);
		log.appendMsg("PDB ambiguous procedure addresses: " + ambiguous.size());
		log.appendMsg("PDB unique mapped procedures: " + entries.size());
		log.appendMsg("PDB ordinary function types: " + procedureCount);
		log.appendMsg("PDB member function types: " + memberCount);
		log.appendMsg("PDB unsupported function types: " + unsupportedCount);
		log.appendMsg("PDB exact existing function entries: " + exactCount);
		log.appendMsg("PDB missing exact function entries: " + (entries.size() - exactCount));
		return List.copyOf(entries.values());
	}
}