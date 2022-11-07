package xexloaderwv;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.swing.SwingConstants;

import org.python.jline.internal.Log;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.DataTypeManagerService;
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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import pdb.symbolserver.ui.LoadPdbDialog;
import pdb.symbolserver.ui.LoadPdbDialog.LoadPdbResults;

public class XEXLoaderWVLoader extends AbstractLibrarySupportLoader {

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		Log.info("XEX Loader: Checking Signature" );
		BinaryReader br = new BinaryReader(provider, false);
		if(br.readInt(0) == 0x58455832)
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("PowerPC:BE:64:VLE-32addr", "default"), true));
		return loadSpecs;
	}

	@Override
	public String getName() {
		return "XEX Loader by Warranty Voider";
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,	Program program, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException 
	{
			try
			{
				Log.info("XEX Loader: Trying to load as retail...");
				LoadXEX(provider, loadSpec, options, program, monitor, log, false);
			}
			catch(Exception e)
			{
				try
				{
					Log.info("XEX Loader: Trying to load as dev kit...");
					LoadXEX(provider, loadSpec, options, program, monitor, log, true);
				}
				catch(Exception e2)
				{
					Log.info("XEX Loader: Failed to load");
					throw new IOException();
				}
			}
	}
	
	public void LoadXEX(ByteProvider provider, LoadSpec loadSpec, List<Option> options,	Program program, TaskMonitor monitor, MessageLog log, boolean isDevKit) throws Exception
	{			
		byte[] buffROM = provider.getInputStream(0).readAllBytes();
		String patchPath = (String)options.get(3).getValue();
		if(!patchPath.equals(""))
			buffROM = ApplyPatch(buffROM, patchPath, options, isDevKit);
		ByteArrayProvider bapROM = new ByteArrayProvider(buffROM);
		Log.info("XEX Loader: Loading header");
		try {		
			XEXHeader h = new XEXHeader(buffROM, options, isDevKit);
			boolean processPData = (boolean)options.get(0).getValue();
			h.ProcessPEImage(program, monitor, log, processPData);
			h.ProcessImportLibraries(program, monitor);
			if((boolean)options.get(1).getValue())
				LoadPDB(program, monitor, (boolean)options.get(2).getValue(), h);
		} catch (Exception e) {
			bapROM.close();
			throw new Exception(e);			
		}
		bapROM.close();
	}
	
	public void LoadPDB(Program program, TaskMonitor monitor, boolean useExperimental, XEXHeader h) throws Exception
	{
		LoadPdbResults loadPdbResults = LoadPdbDialog.choosePdbForProgram(program);
		if (loadPdbResults == null || loadPdbResults.pdbFile == null) 
			return;
		File pdbFile = loadPdbResults.pdbFile;
		if(!useExperimental)
		{
			DataTypeManagerService dataTypeManagerService = AutoAnalysisManager.getAnalysisManager(program).getDataTypeManagerService();
			LoadPdbTask loadPdbTask = new LoadPdbTask(program, pdbFile, loadPdbResults.useMsDiaParser, loadPdbResults.control, dataTypeManagerService);
			TaskBuilder.withTask(loadPdbTask).setStatusTextAlignment(SwingConstants.LEADING).setLaunchDelay(0);
			new TaskLauncher(loadPdbTask, null, 0);
		}
		else
			h.ProcessAdditionalPDB(new PDBFile(pdbFile.getPath(), monitor, program), program, monitor, true, true);
	}
	
	public byte[] ChangeBaseFileFormat(byte[] image) throws Exception
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(image), false);
		int offsetBFF = -1;
		int nOptHeader = b.readInt(20);
		int pos = 24;
		for(int i = 0; i < nOptHeader; i++)
		{
			int id = b.readInt(pos);
			if(id >> 8 == 3)
				offsetBFF = b.readInt(pos + 4);
			pos += 8;
		}
		image[offsetBFF + 5] = 0;
		image[offsetBFF + 7] = 0;
		return image;
	}
	
	public byte[] ApplyPatch(byte[] buffROM, String patchPath, List<Option> options, boolean isDevKit) throws Exception
	{
		Log.info("XEX Loader: Applying patch");
		byte[] buffPatch = Files.readAllBytes(Path.of(patchPath));
		Log.info("XEX Loader: ### Loading Original XEX");
		XEXHeader orgHeader = new XEXHeader(buffROM, options, isDevKit);
		Log.info("XEX Loader: ### Loading Patch XEX");
		XEXHeader patchHeader = new XEXHeader(buffPatch, options, isDevKit);
		if(patchHeader.baseFileFormat.compression == 3)
			{
				XEXPatchDescriptor desc = patchHeader.patchDescriptor;
				byte[] sourceData = new byte[desc.delta_patch.uncompressed_len];
				for(int i = 0; i < desc.delta_patch.uncompressed_len; i++)
					sourceData[i] = buffROM[i + desc.delta_patch.old_addr];
				byte[] patchResult = new LzxDecompression().DecompressLZX(desc.delta_patch.patch_data, sourceData, desc.delta_patch.uncompressed_len);
				for(int i = 0; i < desc.delta_patch.uncompressed_len; i++)
					buffROM[i + desc.delta_patch.new_addr] = patchResult[i];	
				int oldSize = orgHeader.peImage.length + orgHeader.offsetPE;
				int totalSize = orgHeader.offsetPE + patchHeader.loaderInfo.imageSize;
				if(oldSize > totalSize)
					totalSize = oldSize;
				byte[] temp = new byte[totalSize];
				int headerSize = orgHeader.offsetPE;
				for(int i = 0; i < headerSize; i++)
					temp[i] = buffROM[i];
				for(int i = 0; i < orgHeader.peImage.length; i++)
					temp[i + headerSize] = orgHeader.peImage[i];
				buffROM = temp;
				Log.info("XEX Loader: ### Loading XEX with patched header");
				XEXHeader newHeader = new XEXHeader(buffROM, options, isDevKit);
				byte[] newSessionKey = newHeader.sessionKey;
				patchHeader.sessionKey = Helper.AESDecrypt(newSessionKey, patchHeader.loaderInfo.fileKey);
				patchHeader.ReadPEImage(buffPatch);
				BinaryReader b = new BinaryReader(new ByteArrayProvider(patchHeader.peImage), false);
				int nextBlockSize = patchHeader.baseFileFormat.normal.blockSize;
				int pos = 0;
				while(nextBlockSize != 0)
				{
					int currentBlockSize = nextBlockSize;
					nextBlockSize = b.readInt(pos);
					int start = pos;
					pos += 24;
					while(pos < start + currentBlockSize)
					{
						XEXDeltaPatch delta_patch = new XEXDeltaPatch(patchHeader.peImage, pos);
						if(delta_patch.old_addr == 0 && delta_patch.new_addr == 0 && delta_patch.compressed_len == 0 && delta_patch.uncompressed_len == 0)
							break;
						switch(delta_patch.compressed_len)
						{
							case 0:
								for(int i = 0; i < delta_patch.uncompressed_len; i++)
									buffROM[headerSize + delta_patch.new_addr + i] = 0;
								pos += 12;
								break;
							case 1:
								for(int i = 0; i < delta_patch.uncompressed_len; i++)
									buffROM[headerSize + delta_patch.new_addr + i] = buffROM[headerSize + delta_patch.old_addr + i];
								pos += 12;
								break;
							default:
								byte[] patchData = new byte[delta_patch.compressed_len];
								for(int i = 0; i < delta_patch.compressed_len; i++)
									patchData[i] = patchHeader.peImage[pos + i + 12];
								byte[] baseData = new byte[delta_patch.uncompressed_len];
								for(int i = 0; i < delta_patch.uncompressed_len; i++)
									baseData[i] = buffROM[i + delta_patch.old_addr + headerSize];
								patchResult = new LzxDecompression().DecompressLZX(patchData, baseData, delta_patch.uncompressed_len);
								for(int i = 0; i < delta_patch.uncompressed_len; i++)
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
			boolean loadIntoProgram) {
		List<Option> list = new ArrayList<Option>();
		list.add(new Option("Process .pdata", true));
		list.add(new Option("Load PDB File", false));
		list.add(new Option("use experimental PDB loader", false));
		list.add(new Option("Path to xexp", ""));
		return list;
	}
}
