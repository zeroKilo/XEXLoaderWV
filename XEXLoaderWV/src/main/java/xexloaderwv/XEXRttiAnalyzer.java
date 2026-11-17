
package xexloaderwv;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class XEXRttiAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "XEX RTTI Analyzer";
	private static final String DESCRIPTION = "Discovers and reconstructs Xbox 360 Microsoft C++ runtime type information.";
	private static final long MAX_DATA_SIZE = 256L * 1024 * 1024;
	private static final int READ_CHUNK_SIZE = 1024 * 1024;

	public XEXRttiAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(false);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.BLOCK_ANALYSIS);
	}

	private static boolean isSupported(Program program) {
		return "XEX Loader by Warranty Voider".equals(program.getExecutableFormat())
				&& program.getLanguageID().toString().startsWith("PowerPC:BE:")
				&& program.getDataTypeManager().getDataOrganization().getPointerSize() == 4;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return isSupported(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		MessageLog report = new MessageLog();
		try {
			boolean success = process(program, monitor, report);
			if (!success)
				log.appendMsg(report.toString());
			return success;
		} finally {
			Msg.info(this, report.toString());
		}
	}

	public static boolean process(Program program, TaskMonitor monitor, MessageLog report) throws CancelledException {
		if (!isSupported(program)) {
			report.appendMsg("RTTI: unsupported program format or architecture");
			return false;
		}
		long start = System.nanoTime();
		List<XEXRttiDiscovery.Region> data = new ArrayList<>();
		List<XEXRttiDiscovery.Range> code = new ArrayList<>();
		long dataSize = 0;
		var space = program.getAddressFactory().getDefaultAddressSpace();
		try {
			report.appendMsg("XEX RTTI analysis: " + program.getName());
			monitor.setMessage("Collecting XEX memory regions");
			for (var block : program.getMemory().getBlocks()) {
				monitor.checkCancelled();
				if (!block.isInitialized() || block.isOverlay() || !block.getStart().getAddressSpace().equals(space))
					continue;
				long base = block.getStart().getOffset();
				long size = block.getSize();
				if (block.isExecute()) {
					code.add(new XEXRttiDiscovery.Range(base, base + size));
					continue;
				}
				if (size > MAX_DATA_SIZE - dataSize) {
					report.appendMsg("RTTI data size exceeds configured memory limit");
					return false;
				}
				byte[] bytes = new byte[(int) size];
				for (int offset = 0; offset < bytes.length;) {
					monitor.checkCancelled();
					int length = Math.min(READ_CHUNK_SIZE, bytes.length - offset);
					int read = block.getBytes(block.getStart().add(offset), bytes, offset, length);
					if (read != length) {
						report.appendMsg("Incomplete RTTI memory read: " + block.getName());
						return false;
					}
					offset += read;
				}
				data.add(new XEXRttiDiscovery.Region(base, bytes));
				dataSize += size;
			}
			report.appendMsg("RTTI data regions: " + data.size());
			report.appendMsg("RTTI executable regions: " + code.size());
			report.appendMsg("RTTI scanned bytes: " + dataSize);
			if (data.isEmpty() || code.isEmpty()) {
				report.appendMsg("RTTI: no suitable memory regions");
				return true;
			}
			monitor.setMessage("Discovering XEX RTTI structures");
			long discoveryStart = System.nanoTime();
			var result = XEXRttiDiscovery.discover(data, code, monitor::isCancelled);
			report.appendMsg(
					String.format("RTTI discovery elapsed: %.2f seconds", (System.nanoTime() - discoveryStart) / 1e9));
			monitor.checkCancelled();
			XEXRttiApply.apply(program, result, monitor, report);
			return true;
		} catch (CancellationException ex) {
			throw new CancelledException();
		} catch (MemoryAccessException ex) {
			report.appendMsg("RTTI memory access failed: " + ex.getMessage());
			return false;
		} finally {
			report.appendMsg(String.format("RTTI total elapsed: %.2f seconds", (System.nanoTime() - start) / 1e9));
		}
	}
}
