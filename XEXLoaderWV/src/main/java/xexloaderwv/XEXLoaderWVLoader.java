package xexloaderwv;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class XEXLoaderWVLoader extends AbstractLibrarySupportLoader {

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		Msg.info(this, "XEX Loader: Checking Signature");
		BinaryReader br = new BinaryReader(provider, false);
		if (br.readInt(0) == 0x58455832)
			loadSpecs.add(
					new LoadSpec(this, 0, new LanguageCompilerSpecPair("PowerPC:BE:64:A2ALT-32addr", "default"), true));
		return loadSpecs;
	}

	@Override
	public String getName() {
		return "XEX Loader by Warranty Voider";
	}

	@Override
	protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
		XEXHeader header = loadXexImage(settings.provider(), settings.loadSpec(), settings.options(), program,
				settings.monitor(), settings.log());
		List<Option> options = settings.options();
		TaskMonitor monitor = settings.monitor();
		MessageLog log = settings.log();
		String pdbPath = (String) optionValue(options, "Path to PDB/XDB file");
		if (pdbPath != null && !pdbPath.isBlank()) {
			try {
				XEXPdbLoader.apply(Path.of(pdbPath.trim()).toFile(), header, program, monitor, log);
			} catch (CancelledException ex) {
				throw ex;
			} catch (Exception ex) {
				log.appendMsg("PDB/XDB import failed: " + ex);
				Msg.error(this, "XEX Loader: PDB/XDB import failed", ex);
			}
		}
		monitor.checkCancelled();
		String mapPath = (String) optionValue(options, "Path to MAP file");
		if (mapPath != null && !mapPath.isBlank()) {
			try {
				XEXMapLoader.apply(Path.of(mapPath.trim()), program, monitor, log);
			} catch (CancelledException ex) {
				throw ex;
			} catch (IOException | java.nio.file.InvalidPathException ex) {
				log.appendMsg("MAP import failed: " + ex.getMessage());
			}
		}
		monitor.checkCancelled();
		if (Boolean.TRUE.equals(optionValue(options, "Process RTTI"))) {
			try {
				if (!XEXRttiAnalyzer.process(program, monitor, log))
					log.appendMsg("RTTI processing did not complete successfully");
			} catch (CancelledException ex) {
				throw ex;
			} catch (Exception ex) {
				log.appendMsg("RTTI processing failed: " + ex);
				Msg.error(this, "XEX Loader: Optional RTTI processing failed", ex);
			}
		}
	}

	private XEXHeader loadXexImage(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {
		try {
			Msg.info(this, "XEX Loader: Trying to load as retail...");
			return LoadXEX(provider, loadSpec, options, program, monitor, log, false);
		} catch (CancelledException ex) {
			throw ex;
		} catch (Exception e) {
			monitor.checkCancelled();
			if (program.getMemory().getBlocks().length != 0)
				throw new IOException("XEX retail import failed after memory mapping; no devkit retry", e);
			Msg.error(this, "XEX Loader: Retail import failed", e);
			try {
				Msg.info(this, "XEX Loader: Trying to load as dev kit...");
				return LoadXEX(provider, loadSpec, options, program, monitor, log, true);
			} catch (CancelledException ex) {
				throw ex;
			} catch (Exception e2) {
				Msg.error(this, "XEX Loader: Devkit import failed", e2);
				IOException failure = new IOException("XEX import failed for both retail and devkit keys", e2);
				failure.addSuppressed(e);
				throw failure;
			}
		}
	}

	public XEXHeader LoadXEX(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log, boolean isDevKit) throws Exception {
		byte[] buffROM;
		try (var input = provider.getInputStream(0)) {
			buffROM = input.readAllBytes();
		}
		String patchPath = (String) optionValue(options, "Path to xexp");
		if (patchPath != null && !patchPath.isBlank())
			buffROM = ApplyPatch(buffROM, patchPath, options, isDevKit);
		Msg.info(this, "XEX Loader: Loading header");
		XEXHeader h = new XEXHeader(buffROM, options, isDevKit);
		boolean processPData = Boolean.TRUE.equals(optionValue(options, "Process .pdata"));
		h.ProcessPEImage(program, monitor, log, processPData);
		if (h.blocks.isEmpty())
			throw new IOException("XEX image imported without any memory blocks");
		h.ProcessImportLibraries(program, monitor);
		monitor.checkCancelled();
		return h;
	}

	public byte[] ChangeBaseFileFormat(byte[] image) throws Exception {
		BinaryReader b = new BinaryReader(new ByteArrayProvider(image), false);
		int offsetBFF = -1;
		int nOptHeader = b.readInt(20);
		int pos = 24;
		for (int i = 0; i < nOptHeader; i++) {
			int id = b.readInt(pos);
			if (id >> 8 == 3)
				offsetBFF = b.readInt(pos + 4);
			pos += 8;
		}
		image[offsetBFF + 5] = 0;
		image[offsetBFF + 7] = 0;
		return image;
	}

	public byte[] ApplyPatch(byte[] buffROM, String patchPath, List<Option> options, boolean isDevKit)
			throws Exception {
		Msg.info(this, "XEX Loader: Applying patch");
		byte[] buffPatch = Files.readAllBytes(Path.of(patchPath));
		Msg.info(this, "XEX Loader: ### Loading Original XEX");
		XEXHeader orgHeader = new XEXHeader(buffROM, options, isDevKit);
		Msg.info(this, "XEX Loader: ### Loading Patch XEX");
		XEXHeader patchHeader = new XEXHeader(buffPatch, options, isDevKit);
		if (patchHeader.baseFileFormat.compression == 3) {
			XEXPatchDescriptor desc = patchHeader.patchDescriptor;
			byte[] sourceData = new byte[desc.delta_patch.uncompressed_len];
			for (int i = 0; i < desc.delta_patch.uncompressed_len; i++)
				sourceData[i] = buffROM[i + desc.delta_patch.old_addr];
			byte[] patchResult = new LzxDecompression().DecompressLZX(desc.delta_patch.patch_data, sourceData,
					desc.delta_patch.uncompressed_len);
			for (int i = 0; i < desc.delta_patch.uncompressed_len; i++)
				buffROM[i + desc.delta_patch.new_addr] = patchResult[i];
			int oldSize = orgHeader.peImage.length + orgHeader.offsetPE;
			int totalSize = orgHeader.offsetPE + patchHeader.loaderInfo.imageSize;
			if (oldSize > totalSize)
				totalSize = oldSize;
			byte[] temp = new byte[totalSize];
			int headerSize = orgHeader.offsetPE;
			for (int i = 0; i < headerSize; i++)
				temp[i] = buffROM[i];
			for (int i = 0; i < orgHeader.peImage.length; i++)
				temp[i + headerSize] = orgHeader.peImage[i];
			buffROM = temp;
			Msg.info(this, "XEX Loader: ### Loading XEX with patched header");
			XEXHeader newHeader = new XEXHeader(buffROM, options, isDevKit);
			byte[] newSessionKey = newHeader.sessionKey;
			patchHeader.sessionKey = Helper.AESDecrypt(newSessionKey, patchHeader.loaderInfo.fileKey);
			patchHeader.ReadPEImage(buffPatch);
			BinaryReader b = new BinaryReader(new ByteArrayProvider(patchHeader.peImage), false);
			int nextBlockSize = patchHeader.baseFileFormat.normal.blockSize;
			int pos = 0;
			while (nextBlockSize != 0) {
				int currentBlockSize = nextBlockSize;
				nextBlockSize = b.readInt(pos);
				int start = pos;
				pos += 24;
				while (pos < start + currentBlockSize) {
					XEXDeltaPatch delta_patch = new XEXDeltaPatch(patchHeader.peImage, pos);
					if (delta_patch.old_addr == 0 && delta_patch.new_addr == 0 && delta_patch.compressed_len == 0
							&& delta_patch.uncompressed_len == 0)
						break;
					switch (delta_patch.compressed_len) {
					case 0:
						for (int i = 0; i < delta_patch.uncompressed_len; i++)
							buffROM[headerSize + delta_patch.new_addr + i] = 0;
						pos += 12;
						break;
					case 1:
						for (int i = 0; i < delta_patch.uncompressed_len; i++)
							buffROM[headerSize + delta_patch.new_addr + i] = buffROM[headerSize + delta_patch.old_addr
									+ i];
						pos += 12;
						break;
					default:
						byte[] patchData = new byte[delta_patch.compressed_len];
						for (int i = 0; i < delta_patch.compressed_len; i++)
							patchData[i] = patchHeader.peImage[pos + i + 12];
						byte[] baseData = new byte[delta_patch.uncompressed_len];
						for (int i = 0; i < delta_patch.uncompressed_len; i++)
							baseData[i] = buffROM[i + delta_patch.old_addr + headerSize];
						patchResult = new LzxDecompression().DecompressLZX(patchData, baseData,
								delta_patch.uncompressed_len);
						for (int i = 0; i < delta_patch.uncompressed_len; i++)
							buffROM[i + delta_patch.new_addr + headerSize] = patchResult[i];
						pos += 12 + delta_patch.compressed_len;
						break;
					}
				}
				pos = start + currentBlockSize;
			}
		}
		return ChangeBaseFileFormat(buffROM);
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(Option.newBoolean("Process .pdata").value(true).build());
		list.add(new XEXFileOption("Path to PDB/XDB file", "", new String[] { "pdb", "xdb" }, "PDB/XDB File"));
		list.add(new XEXFileOption("Path to xexp", "", "xexp", "XEX Patch File"));
		list.add(new XEXFileOption("Path to MAP file", "", "map", "Microsoft MAP File"));
		list.add(Option.newBoolean("Process RTTI").value(false).build());
		return list;
	}

	private Object optionValue(List<Option> options, String name) {
		for (Option option : options)
			if (option.getName().equals(name))
				return option.getValue();
		return null;
	}

}
