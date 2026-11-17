package xexloaderwv;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class XEXPdbGlobalVariables {
	private static final int S_LDATA32 = 0x110C;
	private static final int S_GDATA32 = 0x110D;
	private static final int MAX_SYMBOL_STREAM = 128 * 1024 * 1024;

	public enum Status {
		READY, EXISTING, PRESERVED, UNSUPPORTED_TYPE, INVALID_RANGE, MISSING_SYMBOL
	}

	public record GlobalEntry(String name, RecordNumber typeRecord, int segment, long sectionOffset, Address address,
			long sectionEnd, long nextSymbolAddress, String sectionName) {
	}

	public record Candidate(GlobalEntry entry, DataType type, Status status, String message) {
	}

	private record DataIdentity(String name, RecordNumber typeRecord) {
	}

	private record RawEntry(String name, RecordNumber typeRecord, int segment, long sectionOffset, Address address,
			long sectionEnd, String sectionName) {
	}

	private XEXPdbGlobalVariables() {
	}

	public static List<GlobalEntry> collectVerified(AbstractPdb pdb, Program program, TaskMonitor monitor,
			MessageLog log) throws Exception {
		if (!(pdb.getDebugInfo() instanceof PdbNewDebugInfo dbi) || dbi.getDebugData() == null)
			throw new IOException("Missing supported DBI information");
		var debug = dbi.getDebugData();
		var sections = debug.getImageSectionHeaders();
		var omap = debug.getOmapFromSource();
		if (debug.getImageSectionHeadersOrig() != null || (omap != null && !omap.isEmpty()))
			throw new IOException("Unsupported data address remapping");
		if (sections == null || sections.isEmpty())
			throw new IOException("Missing PDB section headers");
		var records = dbi.getSymbolRecords();
		int stream = dbi.getSymbolRecordsStreamNumber();
		if (records == null || stream <= 0 || stream == 0xFFFF)
			throw new IOException("Missing PDB symbol stream");
		var reader = pdb.getDeveloperBytes(stream, 0, MAX_SYMBOL_STREAM + 1);
		int streamSize = reader.numRemaining();
		if (streamSize > MAX_SYMBOL_STREAM)
			throw new IOException("PDB symbol stream exceeds supported limit");
		var space = program.getAddressFactory().getDefaultAddressSpace();
		long base = program.getImageBase().getOffset();
		if (base < 0 || base > 0xFFFFFFFFL)
			throw new IOException("Invalid XEX image base");
		TreeMap<Long, RawEntry> entries = new TreeMap<>();
		Set<Long> ambiguous = new HashSet<>();
		int globalCount = 0;
		int staticCount = 0;
		int invalidCount = 0;
		int duplicateCount = 0;
		monitor.initialize(streamSize);
		monitor.setMessage("Collecting PDB global data records");
		while (reader.hasMore()) {
			monitor.checkCancelled();
			int offset = reader.getIndex();
			if (reader.numRemaining() < 4)
				throw new IOException("Truncated PDB symbol record");
			int length = reader.parseUnsignedShortVal();
			if (length < 2 || length > reader.numRemaining())
				throw new IOException("Invalid PDB symbol record length");
			int kind = reader.parseUnsignedShortVal();
			reader.skip(length - 2);
			monitor.setProgress(reader.getIndex());
			if (kind != S_GDATA32 && kind != S_LDATA32)
				continue;
			if (kind == S_GDATA32)
				globalCount++;
			else
				staticCount++;
			var item = records.getRandomAccessRecord(stream, offset);
			if (item == null || item.length() != length + 2 || !(item.symbol() instanceof AbstractDataMsSymbol symbol)
					|| symbol.getPdbId() != kind)
				throw new IOException("Invalid original data symbol");
			int segment = symbol.getSegment();
			long sectionOffset = symbol.getOffset();
			if (segment < 1 || segment > sections.size() || sectionOffset < 0) {
				invalidCount++;
				continue;
			}
			var section = sections.get(segment - 1);
			long flags = section.getCharacteristics();
			long size = section.getUnionPAVS();
			long start = base + section.getVirtualAddress();
			long end = start + size - 1;
			long va = start + sectionOffset;
			if ((flags & 0x20000000L) != 0 || (flags & 0xC0L) == 0 || ".reloc".equals(section.getName()) || size <= 0
					|| sectionOffset >= size || start < base || end < start || end > 0xFFFFFFFFL || va < start
					|| va > end) {
				invalidCount++;
				continue;
			}
			Address address = space.getAddress(va);
			var block = program.getMemory().getBlock(address);
			if (block == null || block.isExecute() || block.getStart().getOffset() != start
					|| block.getSize() != size) {
				invalidCount++;
				continue;
			}
			var entry = new RawEntry(symbol.getName(), symbol.getTypeRecordNumber(), segment, sectionOffset, address,
					end, section.getName());
			var previous = entries.putIfAbsent(va, entry);
			if (previous != null) {
				var oldIdentity = new DataIdentity(previous.name(), previous.typeRecord());
				var newIdentity = new DataIdentity(entry.name(), entry.typeRecord());
				if (oldIdentity.equals(newIdentity))
					duplicateCount++;
				else
					ambiguous.add(va);
			}
		}
		List<GlobalEntry> result = new ArrayList<>();
		for (var item : entries.entrySet()) {
			monitor.checkCancelled();
			if (ambiguous.contains(item.getKey()))
				continue;
			var raw = item.getValue();
			Long next = entries.higherKey(item.getKey());
			result.add(new GlobalEntry(raw.name(), raw.typeRecord(), raw.segment(), raw.sectionOffset(), raw.address(),
					raw.sectionEnd(), next == null ? 0x100000000L : next, raw.sectionName()));
		}
		log.appendMsg("PDB global data records: " + globalCount);
		log.appendMsg("PDB static data records: " + staticCount);
		log.appendMsg("PDB invalid data addresses: " + invalidCount);
		log.appendMsg("PDB repeated data identities: " + duplicateCount);
		log.appendMsg("PDB unique data addresses: " + entries.size());
		log.appendMsg("PDB ambiguous data addresses: " + ambiguous.size());
		log.appendMsg("PDB mapped data candidates: " + result.size());
		return List.copyOf(result);
	}

	public static Candidate inspect(Program program, XEXPdbTypeResolver resolver, GlobalEntry entry,
			TaskMonitor monitor) throws Exception {
		monitor.checkCancelled();
		if (!".data".equals(entry.sectionName()) && !".rdata".equals(entry.sectionName()))
			return new Candidate(entry, null, Status.INVALID_RANGE, "Special data section deferred");
		if (entry.name() == null || entry.name().isBlank() || entry.name().startsWith("__@@_PchSym_"))
			return new Candidate(entry, null, Status.PRESERVED, "Compiler-generated or unnamed symbol");
		if (program.getSymbolTable().getGlobalSymbol(entry.name(), entry.address()) == null)
			return new Candidate(entry, null, Status.MISSING_SYMBOL, "No matching original symbol");
		DataType type;
		try {
			type = resolver.reconstructDataType(entry.typeRecord());
		} catch (XEXPdbTypeResolver.UnsupportedTypeException ex) {
			return new Candidate(entry, null, Status.UNSUPPORTED_TYPE, ex.getMessage());
		} catch (IllegalArgumentException | ArithmeticException ex) {
			return new Candidate(entry, null, Status.UNSUPPORTED_TYPE, "Invalid data type geometry");
		}
		int size = type.getLength();
		long start = entry.address().getOffset();
		long end = start + size - 1L;
		if (size <= 0 || end < start || end > entry.sectionEnd() || end >= entry.nextSymbolAddress())
			return new Candidate(entry, type, Status.INVALID_RANGE, "Data extends beyond validated boundaries");
		Address endAddress = entry.address().add(size - 1L);
		var block = program.getMemory().getBlock(entry.address());
		if (block == null || !block.isInitialized() || block.isExecute() || end > block.getEnd().getOffset())
			return new Candidate(entry, type, Status.INVALID_RANGE, "Invalid initialized data range");
		var listing = program.getListing();
		var existing = listing.getDefinedDataAt(entry.address());
		if (existing != null && existing.getLength() == size && existing.getDataType().isEquivalent(type))
			return new Candidate(entry, type, Status.EXISTING, "Equivalent data already exists");
		if (!listing.isUndefined(entry.address(), endAddress))
			return new Candidate(entry, type, Status.PRESERVED, "Existing data or instructions preserved");
		return new Candidate(entry, type, Status.READY, "Data type and memory range validated");
	}
}