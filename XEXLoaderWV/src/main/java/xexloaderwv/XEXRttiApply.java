
package xexloaderwv;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public final class XEXRttiApply {
	private static final CategoryPath CATEGORY = new CategoryPath("/XEX/RTTI");
	private final Program program;
	private final TaskMonitor monitor;
	private final MessageLog log;
	private final DataTypeManager dtm;
	private final DataType ptr;
	private final DataType u32 = DWordDataType.dataType;
	private final DataType s32 = SignedDWordDataType.dataType;
	private int created;
	private int existing;
	private int skipped;
	private int labels;
	private int preservedLabels;
	private int failedLabels;

	private XEXRttiApply(Program program, TaskMonitor monitor, MessageLog log) {
		this.program = program;
		this.monitor = monitor;
		this.log = log;
		this.dtm = program.getDataTypeManager();
		this.ptr = new PointerDataType(null, 4, dtm);
	}

	public static void apply(Program program, XEXRttiDiscovery.Result result, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		new XEXRttiApply(program, monitor, log).run(result);
	}

	private DataType structure(String name, String[] fields, DataType... types) {
		StructureDataType structure = new StructureDataType(CATEGORY, name, 0, dtm);
		structure.setPackingEnabled(false);
		for (int i = 0; i < fields.length; i++)
			structure.add(types[i], 4, fields[i], null);
		if (structure.getLength() != fields.length * 4)
			throw new IllegalStateException("Unexpected RTTI structure size: " + name);
		return dtm.resolve(structure, DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	private Address address(long value) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
	}

	private boolean define(long value, DataType type) throws CancelledException {
		monitor.checkCancelled();
		Address start = address(value);
		Address end = start.add(type.getLength() - 1L);
		var block = program.getMemory().getBlock(start);
		if (block == null || !block.isInitialized() || block.isExecute() || !block.contains(end)) {
			skipped++;
			return false;
		}
		var listing = program.getListing();
		var data = listing.getDefinedDataContaining(start);
		if (data != null) {
			if (data.getMinAddress().equals(start) && data.getLength() == type.getLength()
					&& data.getDataType().isEquivalent(type)) {
				existing++;
				return true;
			}
			skipped++;
			return false;
		}
		var next = listing.getDefinedDataAfter(start);
		if ((next != null && next.getMinAddress().compareTo(end) <= 0) || !listing.isUndefined(start, end)) {
			skipped++;
			return false;
		}
		try {
			if (listing.createData(start, type) == null) {
				skipped++;
				return false;
			}
			created++;
			return true;
		} catch (CodeUnitInsertionException ex) {
			skipped++;
			if (skipped <= 5)
				log.appendMsg("RTTI data skipped at " + start + ": " + ex.getMessage());
			return false;
		}
	}

	private void mark(long value, String prefix, String typeName, String comment) {
		Address addr = address(value);
		var listing = program.getListing();
		var symbols = program.getSymbolTable();
		String shortName = typeName.startsWith(".?A") && typeName.length() > 4 ? typeName.substring(4) : typeName;
		shortName = shortName.replaceAll("[^A-Za-z0-9_]", "_");
		if (shortName.length() > 80)
			shortName = shortName.substring(0, 80);
		String label = String.format("%s_%s_%08X", prefix, shortName, value);
		var primary = symbols.getPrimarySymbol(addr);
		if ((primary != null && !primary.isDynamic()) || program.getFunctionManager().getFunctionAt(addr) != null) {
			preservedLabels++;
		} else {
			try {
				symbols.createLabel(addr, label, SourceType.ANALYSIS);
				labels++;
			} catch (InvalidInputException ex) {
				failedLabels++;
				if (failedLabels <= 5)
					log.appendMsg("RTTI label failed at " + addr + ": " + ex.getMessage());
			}
		}
		if (listing.getComment(CommentType.PLATE, addr) == null)
			listing.setComment(addr, CommentType.PLATE, comment);
	}

	private void run(XEXRttiDiscovery.Result result) throws CancelledException {
		long start = System.nanoTime();
		if (result.types().isEmpty()) {
			log.appendMsg("RTTI: no validated type descriptors found");
			return;
		}
		DataType rtti0 = structure("RTTI0_TypeDescriptorHeader", new String[] { "pVFTable", "spare" }, ptr, ptr);
		DataType rtti1 = structure("RTTI1_BaseClassDescriptor", new String[] { "pTypeDescriptor", "numContainedBases",
				"mdisp", "pdisp", "vdisp", "attributes", "pClassHierarchy" }, ptr, u32, s32, s32, s32, u32, ptr);
		DataType rtti3 = structure("RTTI3_ClassHierarchyDescriptor",
				new String[] { "signature", "attributes", "numBaseClasses", "pBaseClassArray" }, u32, u32, u32, ptr);
		DataType rtti4 = structure("RTTI4_CompleteObjectLocator",
				new String[] { "signature", "offset", "cdOffset", "pTypeDescriptor", "pClassHierarchy" }, u32, u32, u32,
				ptr, ptr);
		Map<Long, String> names = new TreeMap<>();
		Map<Long, XEXRttiDiscovery.Locator> locators = new TreeMap<>();
		Set<Long> appliedBases = new HashSet<>();
		Set<Long> appliedArrays = new HashSet<>();
		monitor.setMessage("Applying RTTI type descriptors");
		for (var type : result.types()) {
			monitor.checkCancelled();
			names.put(type.address(), type.name());
			if (define(type.address(), rtti0))
				mark(type.address(), "RTTI0", type.name(), "RTTI type descriptor: " + type.name());
			int length = type.name().length() + 1;
			define(type.address() + 8, new ArrayDataType(CharDataType.dataType, length, 1, dtm));
		}
		monitor.setMessage("Applying RTTI class hierarchies");
		for (var hierarchy : result.hierarchies()) {
			monitor.checkCancelled();
			String owner = names.getOrDefault(hierarchy.bases().get(0).type(), "unknown");
			if (define(hierarchy.address(), rtti3))
				mark(hierarchy.address(), "RTTI3", owner,
						"RTTI class hierarchy: " + owner + "\nBase descriptors: " + hierarchy.bases().size());
			if (appliedArrays.add(hierarchy.array())) {
				DataType array = new ArrayDataType(ptr, hierarchy.bases().size(), 4, dtm);
				if (define(hierarchy.array(), array))
					mark(hierarchy.array(), "RTTI2", owner, "RTTI base class array: " + owner);
			}
			for (var base : hierarchy.bases()) {
				monitor.checkCancelled();
				if (!appliedBases.add(base.address()))
					continue;
				String name = names.getOrDefault(base.type(), "unknown");
				if (define(base.address(), rtti1))
					mark(base.address(), "RTTI1", name, "RTTI base class descriptor: " + name);
			}
		}
		monitor.setMessage("Applying RTTI complete object locators");
		for (var locator : result.locators()) {
			monitor.checkCancelled();
			locators.put(locator.address(), locator);
			String name = names.getOrDefault(locator.type(), "unknown");
			if (define(locator.address(), rtti4))
				mark(locator.address(), "RTTI4", name, "RTTI complete object locator: " + name);
		}
		monitor.setMessage("Applying RTTI-linked virtual tables");
		for (var table : result.tables()) {
			monitor.checkCancelled();
			var locator = locators.get(table.locator());
			if (locator == null)
				continue;
			String name = names.getOrDefault(locator.type(), "unknown");
			define(table.address() - 4, ptr);
			if (define(table.address(), ptr))
				mark(table.address(), "vftable", name, "RTTI-linked virtual function table: " + name
						+ "\nOnly the first function pointer is validated");
		}
		log.appendMsg("RTTI type descriptors: " + result.types().size());
		log.appendMsg("RTTI base class descriptors: " + appliedBases.size());
		log.appendMsg("RTTI base class arrays: " + appliedArrays.size());
		log.appendMsg("RTTI class hierarchies: " + result.hierarchies().size());
		log.appendMsg("RTTI complete object locators: " + result.locators().size());
		log.appendMsg("RTTI-linked virtual tables: " + result.tables().size());
		log.appendMsg("RTTI data units created: " + created);
		log.appendMsg("RTTI existing data units: " + existing);
		log.appendMsg("RTTI skipped data units: " + skipped);
		log.appendMsg("RTTI labels created: " + labels);
		log.appendMsg("RTTI existing labels preserved: " + preservedLabels);
		log.appendMsg("RTTI failed labels: " + failedLabels);
		log.appendMsg(String.format("RTTI application elapsed: %.2f seconds", (System.nanoTime() - start) / 1e9));
	}
}
