
package xexloaderwv;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordCategory;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.TypeProgramInterface;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractComplexMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractCompositeMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractEnumMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class XEXPdbTypeCatalog {
	public record TypeEntry(int index, int kind, String name, String uniqueName, boolean forward, BigInteger size,
			RecordNumber fieldList) {
	}

	private record TypeKey(int kind, String uniqueName) {
	}

	private final TypeProgramInterface tpi;
	private final Map<Integer, TypeEntry> entries = new TreeMap<>();
	private final Map<Integer, Integer> aliases = new HashMap<>();
	private int forwards;
	private int definitions;
	private int ambiguous;
	private int unresolved;

	private XEXPdbTypeCatalog(TypeProgramInterface tpi) {
		this.tpi = tpi;
	}

	public static XEXPdbTypeCatalog build(AbstractPdb pdb, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		var tpi = pdb.getTypeProgramInterface();
		if (tpi == null)
			throw new IllegalArgumentException("Missing PDB type stream");
		var catalog = new XEXPdbTypeCatalog(tpi);
		catalog.collect(monitor);
		catalog.resolveForwards(monitor);
		catalog.report(log);
		return catalog;
	}

	private void collect(TaskMonitor monitor) throws CancelledException {
		int first = tpi.getTypeIndexMin();
		int last = tpi.getTypeIndexMaxExclusive();
		monitor.setMessage("Collecting PDB type identities");
		monitor.initialize(last - first);
		for (int index = first; index < last; index++) {
			monitor.checkCancelled();
			var raw = tpi.getRandomAccessRecord(index);
			if (raw instanceof AbstractComplexMsType type
					&& (raw instanceof AbstractCompositeMsType || raw instanceof AbstractEnumMsType)) {
				var property = type.getMsProperty();
				boolean forward = property.isForwardReference();
				String uniqueName = property.hasUniqueName() ? type.getMangledName() : null;
				BigInteger size = raw instanceof AbstractCompositeMsType composite ? composite.getSize() : null;
				var entry = new TypeEntry(index, type.getPdbId(), type.getName(), uniqueName, forward, size,
						type.getFieldDescriptorListRecordNumber());
				entries.put(index, entry);
				if (forward)
					forwards++;
				else
					definitions++;
			}
			monitor.incrementProgress(1);
		}
	}

	private TypeKey key(TypeEntry entry) {
		if (entry.uniqueName() == null || entry.uniqueName().isEmpty())
			return null;
		return new TypeKey(entry.kind(), entry.uniqueName());
	}

	private void resolveForwards(TaskMonitor monitor) throws CancelledException {
		Map<TypeKey, List<TypeEntry>> candidates = new HashMap<>();
		monitor.setMessage("Indexing PDB type definitions");
		for (var entry : entries.values()) {
			monitor.checkCancelled();
			TypeKey key = key(entry);
			if (!entry.forward() && key != null)
				candidates.computeIfAbsent(key, k -> new ArrayList<>()).add(entry);
		}
		monitor.setMessage("Resolving PDB forward declarations");
		monitor.initialize(forwards);
		for (var entry : entries.values()) {
			monitor.checkCancelled();
			if (!entry.forward())
				continue;
			TypeKey key = key(entry);
			List<TypeEntry> matches = key == null ? List.of() : candidates.getOrDefault(key, List.of());
			if (matches.size() > 1) {
				ambiguous++;
			} else if (matches.size() == 1 && java.util.Objects.equals(entry.name(), matches.get(0).name())) {
				aliases.put(entry.index(), matches.get(0).index());
			} else {
				unresolved++;
			}
			monitor.incrementProgress(1);
		}
	}

	public int canonicalIndex(int index) {
		return aliases.getOrDefault(index, index);
	}

	public TypeEntry getEntry(int index) {
		return entries.get(canonicalIndex(index));
	}

	public List<TypeEntry> getDefinitions() {
		return entries.values().stream().filter(e -> !e.forward()).toList();
	}

	public AbstractMsType getRecord(RecordNumber number) {
		if (number == null || number.getCategory() != RecordCategory.TYPE)
			throw new IllegalArgumentException("Expected a TPI record number");
		int index = canonicalIndex(number.getNumber());
		if (index < 0 || index >= tpi.getTypeIndexMaxExclusive())
			throw new IllegalArgumentException("Invalid TPI index: " + index);
		return tpi.getRandomAccessRecord(index);
	}

	public boolean isUnresolvedForward(int index) {
		var entry = entries.get(index);
		return entry != null && entry.forward() && !aliases.containsKey(index);
	}

	private void report(MessageLog log) {
		log.appendMsg("PDB type records: " + (tpi.getTypeIndexMaxExclusive() - tpi.getTypeIndexMin()));
		log.appendMsg("PDB complex type records: " + entries.size());
		log.appendMsg("PDB type definitions: " + definitions);
		log.appendMsg("PDB forward declarations: " + forwards);
		log.appendMsg("PDB resolved forwards: " + aliases.size());
		log.appendMsg("PDB ambiguous forwards: " + ambiguous);
		log.appendMsg("PDB unresolved forwards: " + unresolved);
	}
}
