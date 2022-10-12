package xexloaderwv;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.python.jline.internal.Log;

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
import ghidra.util.task.TaskMonitor;

public class XEXLoaderWVLoader extends AbstractLibrarySupportLoader {

	private byte[] oldFileKey;
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
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
			try
			{
				Log.info("XEX Loader: Trying to load as dev kit...");
				LoadXEX(provider, loadSpec, options, program, monitor, log, true);
			}
			catch(Exception e)
			{
				try
				{
					Log.info("XEX Loader: Trying to load as retail...");
					LoadXEX(provider, loadSpec, options, program, monitor, log, false);
				}
				catch(Exception e2)
				{
					Log.info("XEX Loader: Failed to load");
					throw new IOException();
				}
			}
		
	}
	
	public void LoadXEX(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log, boolean isDevKit) throws Exception
	{
		oldFileKey = null;
		byte[] buffROM = provider.getInputStream(0).readAllBytes();
		String patchPath = (String)options.get(2).getValue();
		if(!patchPath.equals(""))
		{
			Log.info("XEX Loader: Applying patch");
			buffROM = ApplyPatch(buffROM, patchPath, options, isDevKit);
			Files.write(Paths.get("C:\\test.bin"), buffROM);
		}
		ByteArrayProvider bapROM = new ByteArrayProvider(buffROM);
		Log.info("XEX Loader: Loading header");
		try {		
			XEXHeader h = new XEXHeader(buffROM, options, isDevKit, oldFileKey);
			boolean processPData = (boolean)options.get(0).getValue();
			h.ProcessPEImage(program, monitor, log, processPData);
			h.ProcessImportLibraries(program, monitor);
			String pdbPath = (String)options.get(1).getValue();
			if(!pdbPath.equals(""))
				h.ProcessAdditionalPDB(new PDBFile(pdbPath, monitor), program, monitor);
		} catch (Exception e) {
			bapROM.close();
			throw new Exception(e);			
		}
		bapROM.close();
	}
	
	public byte[] ApplyPatch(byte[] buffROM, String patchPath, List<Option> options, boolean isDevKit) throws Exception
	{
		byte[] buffPatch = Files.readAllBytes(Path.of(patchPath));
		ByteArrayProvider bapROM = new ByteArrayProvider(buffROM);
		ByteArrayProvider bapPatch = new ByteArrayProvider(buffPatch);
		try
		{
			XEXHeader baseHeader = new XEXHeader(buffROM, options, isDevKit, null);
			oldFileKey = baseHeader.loaderInfo.fileKey;
			XEXHeader patchHeader = new XEXHeader(buffPatch, options, isDevKit, null);
			if(patchHeader.baseFileFormat.compression == 3)
				for(XEXPatchDescriptor desc : patchHeader.patchDescriptors)
				{
					byte[] sourceData = new byte[desc.uncompressed_len];
					for(int i = 0; i < desc.uncompressed_len; i++)
						sourceData[i] = buffROM[i + desc.old_addr];
					byte[] patchResult = new LzxDecompression().DecompressLZX(desc.patch_data, sourceData, desc.uncompressed_len);
					for(int i = 0; i < desc.uncompressed_len; i++)
						buffROM[i + desc.new_addr] = patchResult[i];
					
				}
		} catch (Exception e) {
			bapROM.close();
			bapPatch.close();
			throw new Exception(e);				
		}
		bapROM.close();
		bapPatch.close();
		return buffROM;
	}
	
	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean loadIntoProgram) {
		List<Option> list = new ArrayList<Option>();
		list.add(new Option("Process .pdata", true));
		list.add(new Option("Path to pdb", ""));
		list.add(new Option("Path to xexp", ""));
		return list;
	}
}
