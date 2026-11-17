
package xexloaderwv;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.data.DataUtilities;

public final class XEXPdbMetadataApply {
	private XEXPdbMetadataApply() {
	}

	public static void apply(AbstractPdb pdb, Program program, TaskMonitor monitor, MessageLog log) throws Exception {
		monitor.checkCancelled();
		var catalog = XEXPdbTypeCatalog.build(pdb, monitor, log);
		var resolver = new XEXPdbTypeResolver(catalog, program.getDataTypeManager(), monitor);
		var types = resolver.buildTypes(log);
		int imported = 0;
		int deferred = 0;
		monitor.initialize(types.size());
		monitor.setMessage("Registering verified PDB data types");
		for (var entry : types.entrySet()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			var original = entry.getValue();
			if (original == null || original.getLength() <= 0) {
				deferred++;
				continue;
			}
			var resolved = program.getDataTypeManager().resolve(original, DataTypeConflictHandler.DEFAULT_HANDLER);
			if (resolved == null || resolved.getLength() != original.getLength())
				throw new IOException("PDB type layout mismatch: TPI 0x" + Integer.toHexString(entry.getKey()));
			imported++;
		}
		log.appendMsg("PDB persisted data types: " + imported);
		log.appendMsg("PDB deferred zero-sized data types: " + deferred);
		var functions = XEXPdbFunctionCatalog.collectVerified(pdb, program, monitor, log);
		createMissingFunctions(program, functions, monitor, log);
		applyFunctionSignatures(program, catalog, resolver, functions, monitor, log);
		var globals = XEXPdbGlobalVariables.collectVerified(pdb, program, monitor, log);
		applyGlobalVariables(program, resolver, globals, monitor, log);
	}

	private static void createMissingFunctions(Program program, List<XEXPdbFunctionCatalog.FunctionEntry> entries,
			TaskMonitor monitor, MessageLog log) throws Exception {
		var manager = program.getFunctionManager();
		var listing = program.getListing();
		Set<Long> knownStarts = new HashSet<>();
		for (var entry : entries)
			knownStarts.add(entry.address().getOffset());
		int inspected = 0;
		int created = 0;
		for (var entry : entries) {
			monitor.checkCancelled();
			if (inspected >= 64 || created >= 8)
				break;
			var address = entry.address();
			if (manager.getFunctionContaining(address) != null || listing.getInstructionAt(address) == null)
				continue;
			var block = program.getMemory().getBlock(address);
			if (block == null || !block.isExecute() || !".text".equals(block.getName()))
				continue;
			inspected++;
			AddressSetView body = CreateFunctionCmd.getFunctionBody(program, address, false, monitor);
			if (body == null || !body.contains(address) || body.getNumAddresses() < 8 || body.getNumAddresses() > 0x2000
					|| body.getNumAddresses() > entry.length() || manager.getFunctionsOverlapping(body).hasNext())
				continue;
			long decodedBytes = 0;
			boolean terminal = false;
			boolean valid = true;
			var instructions = listing.getInstructions(body, true);
			while (instructions.hasNext()) {
				monitor.checkCancelled();
				Instruction instruction = instructions.next();
				var instructionAddress = instruction.getAddress();
				var instructionBlock = program.getMemory().getBlock(instructionAddress);
				if (instruction.getLength() != 4 || instructionBlock == null || !instructionBlock.isExecute()
						|| !".text".equals(instructionBlock.getName())
						|| manager.getFunctionContaining(instructionAddress) != null
						|| (!instructionAddress.equals(address)
								&& knownStarts.contains(instructionAddress.getOffset()))) {
					valid = false;
					break;
				}
				decodedBytes += instruction.getLength();
				if (instruction.getFlowType().isTerminal())
					terminal = true;
			}
			if (!valid || !terminal || decodedBytes != body.getNumAddresses())
				continue;
			var function = manager.createFunction(null, address, body, SourceType.ANALYSIS);
			if (function == null || !function.getBody().hasSameAddresses(body))
				throw new IOException("PDB function creation failed at " + address);
			created++;
			log.appendMsg("PDB created function: " + address + " " + function.getName());
		}
		log.appendMsg("PDB function bodies inspected: " + inspected);
		log.appendMsg("PDB functions created: " + created);
	}

	private static void applyFunctionSignatures(Program program, XEXPdbTypeCatalog catalog, XEXPdbTypeResolver resolver,
			List<XEXPdbFunctionCatalog.FunctionEntry> functions, TaskMonitor monitor, MessageLog log) throws Exception {
		final int maxApplications = 2048;
		Map<XEXPdbFunctionApply.Status, Integer> counts = new TreeMap<>();
		int applied = 0;
		int deferred = 0;
		monitor.initialize(functions.size());
		monitor.setMessage("Applying verified PDB function signatures");
		for (var entry : functions) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			if (applied >= maxApplications) {
				deferred++;
				continue;
			}
			var result = XEXPdbFunctionApply.process(program, catalog, resolver, entry, true, monitor);
			counts.merge(result.status(), 1, Integer::sum);
			if (result.status() == XEXPdbFunctionApply.Status.APPLIED)
				applied++;
		}
		log.appendMsg("PDB function signature outcomes: " + counts);
		log.appendMsg("PDB function signatures applied: " + applied);
		log.appendMsg("PDB signature entries deferred by limit: " + deferred);
	}

	private static void applyGlobalVariables(Program program, XEXPdbTypeResolver resolver,
			List<XEXPdbGlobalVariables.GlobalEntry> globals, TaskMonitor monitor, MessageLog log) throws Exception {
		final int maxApplications = 2048;
		final int maxTypeBytes = 0x10000;
		Map<XEXPdbGlobalVariables.Status, Integer> counts = new TreeMap<>();
		int applied = 0;
		int deferred = 0;
		int skippedSize = 0;
		monitor.initialize(globals.size());
		monitor.setMessage("Applying verified PDB global variable types");
		for (var entry : globals) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			if (applied >= maxApplications) {
				deferred++;
				continue;
			}
			var candidate = XEXPdbGlobalVariables.inspect(program, resolver, entry, monitor);
			counts.merge(candidate.status(), 1, Integer::sum);
			if (candidate.status() != XEXPdbGlobalVariables.Status.READY)
				continue;
			var type = candidate.type();
			int length = type.getLength();
			if (length <= 0 || length > maxTypeBytes) {
				skippedSize++;
				continue;
			}
			var address = entry.address();
			if (!program.getListing().isUndefined(address, address.add(length - 1)))
				continue;
			var resolved = program.getDataTypeManager().resolve(type, DataTypeConflictHandler.DEFAULT_HANDLER);
			if (resolved == null || resolved.getLength() != length)
				throw new IOException("PDB global type size changed at " + address);
			byte[] before = new byte[length];
			if (program.getMemory().getBytes(address, before) != length)
				throw new IOException("Unable to read original global data at " + address);
			var data = DataUtilities.createData(program, address, resolved, length,
					DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			if (data == null || data.getLength() != length || !data.getDataType().isEquivalent(resolved))
				throw new IOException("PDB global type application failed at " + address);
			byte[] after = new byte[length];
			if (program.getMemory().getBytes(address, after) != length || !java.util.Arrays.equals(before, after))
				throw new IOException("Global data bytes changed at " + address);
			applied++;
			if (applied <= 8)
				log.appendMsg("PDB applied global type: " + address + " " + entry.name());
		}
		log.appendMsg("PDB global inspection outcomes: " + counts);
		log.appendMsg("PDB global types applied: " + applied);
		log.appendMsg("PDB global applications deferred by limit: " + deferred);
		log.appendMsg("PDB globals skipped by size: " + skippedSize);
	}

}
