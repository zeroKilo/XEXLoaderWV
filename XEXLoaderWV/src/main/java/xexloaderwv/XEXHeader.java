package xexloaderwv;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.python.jline.internal.Log;

import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.task.TaskMonitor;
import xexloaderwv.PDBFile.SymbolRecord;

public class XEXHeader {
	public int magic;
	public int flags;
	public int offsetPE;
	public int reserved;
	public int offsetSecuInfo;
	public int nOptHeader;
	public ArrayList<XEXOptionalHeader> optHeaders = new ArrayList<XEXOptionalHeader>();
	public BaseFileFormat baseFileFormat;
	public XEXLoaderInfo loaderInfo;
	public byte[] sessionKey;
	public ArrayList<XEXSection> sections = new ArrayList<XEXSection>();
	public byte[] peImage;
	public int imageBaseAddress;
	public int entryPointAddress;
	public ArrayList<String> stringTable;
	public ArrayList<ImportLibrary> importLibs;
	
	public XEXHeader(byte[] data, List<Option> list) throws Exception
	{
		LZXHelper.Init();
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		magic = b.readInt(0);
		flags = b.readInt(4);
		offsetPE = b.readInt(8);
		reserved = b.readInt(12);
		offsetSecuInfo = b.readInt(16);
		nOptHeader = b.readInt(20);
		Log.info("XEX Loader: Loading optional headers");
		int pos = 24;
		for(int i = 0; i < nOptHeader; i++)
		{
			optHeaders.add(new XEXOptionalHeader(data, pos));
			pos += 8;
		}
		for(int i = 0; i < nOptHeader; i++)
		{
			XEXOptionalHeader oh = optHeaders.get(i);
			int test = oh.id & 0xFF;
			if(test == 0xFF)
			{
				int len = b.readInt(oh.value);
				oh.data = b.readByteArray(oh.value, len);
			}
			else if (test < 2)
				oh.data = b.readByteArray(24 + i * 8 + 4, 4);
			else
			{
				int len = test * 4;
				oh.data = b.readByteArray(oh.value, len);	
			}
		}
		ProcessOptionalHeaders();
		Log.info("XEX Loader: Loading loader info");
		loaderInfo = new XEXLoaderInfo(data, offsetSecuInfo, list);
		DecryptFileKey();
		Log.info("XEX Loader: Loading section info");
		int sectionCount = b.readInt(offsetSecuInfo + 0x180);
		for(int i=0; i < sectionCount; i++)
			sections.add(new XEXSection(data, offsetSecuInfo + (i * 24) + 0x184));			
		ReadPEImage(data);
	}
	
	public void DecryptFileKey() throws Exception
	{
		byte[] key;
		if(loaderInfo.isDevKit)
			key = new byte[16];
		else
			key  = Helper.hexStringToByteArray("20B185A59D28FDC340583FBB0896BF91");
		String s = "";
		for(byte b : loaderInfo.fileKey)
			s += String.format("%02X ", b);
		Log.info("XEX Loader: File key    = " + s);	
		sessionKey = Helper.AESDecrypt(key, loaderInfo.fileKey);
		s = "";
		for(byte b : sessionKey)
			s += String.format("%02X ", b);
		Log.info("XEX Loader: Session key = " + s);		
	}
	
	public void ProcessOptionalHeaders() throws Exception
	{
		Log.info("XEX Loader: Processing section info");
		for(XEXOptionalHeader sec : optHeaders)
		{
			BinaryReader b = null;
			if(sec.data != null)
				b = new BinaryReader(new ByteArrayProvider(sec.data), false);
			switch(sec.id >> 8)
			{
				case 0x3:
					baseFileFormat = new BaseFileFormat(sec.data);				
					break;
				case 0x101:					
					entryPointAddress = b.readInt(0);
					Log.info("XEX Loader: Entry point address = 0x" + String.format("%08X", entryPointAddress));
					break;
				case 0x102:
					imageBaseAddress = b.readInt(0);
					Log.info("XEX Loader: Imagebase address = 0x" + String.format("%08X", imageBaseAddress));
					break;
				case 0x103:
					ReadImportLibraries(sec.data);
					break;
			}
		}
	}
	
	public void ProcessAdditionalPDB(PDBFile pdb, Program program) throws Exception
	{
		DOSHeader dos = new DOSHeader(peImage);
		NTHeader nt = new NTHeader(peImage, dos.e_lfanew);
		int address = imageBaseAddress;
		for(NTHeader.SectionHeader sec : nt.secHeaders)
			if(sec.Name.equals(".text"))
			{
				address += sec.VirtualAddress;
				break;
			}
		int count = 0;
		for(SymbolRecord sym : pdb.symbols)
			if(sym.pubsymflags == 2 && sym.rectyp == 0x110e)
			{
				count++;
				Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address + sym.off);
				SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, addr, null, sym.name, SourceType.ANALYSIS);
			}	
		Log.info("XEX Loader: Loaded " + count + " pdb function symbols");	
	}
	
	public void ProcessImportLibraries(MemoryBlockUtil mbu, Program program, TaskMonitor monitor) throws Exception
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(peImage), false);
		for(ImportLibrary lib : importLibs)
		{
			for(int i = 0; i < lib.records.size(); i++)
			{
				int address = lib.records.get(i) - imageBaseAddress;
				int value = b.readInt(address);
				int ordinal = value & 0xFFFF;
				int type = value >> 24;
				ImportFunction ipf;
				switch(type)
				{
					case 0:
						ipf = new ImportFunction();
						ipf.address = lib.records.get(i);
						ipf.ordinal = ordinal;
						ipf.thunk = 0;
						lib.functions.add(ipf);
						break;
					case 1:
						ipf = lib.functions.get(lib.functions.size() - 1);
						ipf.thunk =  lib.records.get(i);
						break;
				}
			}
		}
		int countImpl = 0;
		int countThunk = 0;
		for(ImportLibrary lib : importLibs)
		{
			for(ImportFunction fun : lib.functions)
			{
				Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(fun.address);
				SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, addr, null, "__imp__" + ImportRenamer.Rename(lib.name, fun.ordinal) , SourceType.IMPORTED);
				countImpl++;
				if(fun.thunk != 0)
				{
					int pos = fun.thunk - imageBaseAddress;
					peImage[pos] = 0x38;
					peImage[pos + 1] = 0x60;
					peImage[pos + 4] = 0x38;
					peImage[pos + 5] = (byte)0x80;
					addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(fun.thunk);
					SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, addr, null, ImportRenamer.Rename(lib.name, fun.ordinal) , SourceType.ANALYSIS);
					countThunk++;
				}
			}
		}
		Log.info("XEX Loader: Added import symbols(" + countImpl + " References, " + countThunk + " Thunks)");
	}
	
	public void ReadStringTable(byte[] data, int start, int len) throws Exception
	{
		stringTable = new ArrayList<String>();
		int pos = start;
		String s = "";
		while(pos < start + len)
		{
			if(data[pos] != 0)
				s += (char)data[pos];
			else
			{
				stringTable.add(s);
				s = "";
			}
			pos++;
		}
	}
	
	public void ReadImportLibraries(byte[] data) throws Exception
	{
		importLibs = new ArrayList<ImportLibrary>();
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		int pos = 4;
		int stringSize = b.readInt(pos);
		int libCount = b.readInt(pos + 4);
		pos += 8;
		ReadStringTable(data, pos, stringSize);
		pos += stringSize;
		for(int i = 0; i < libCount; i++)
		{
			ImportLibrary lib = new ImportLibrary();
			pos += 0x24;
			short nameIdx = b.readShort(pos);
			short count = b.readShort(pos + 2);
			pos += 4;
			lib.name = stringTable.get(nameIdx);
			for(int j = 0; j < count; j++)
				lib.records.add(b.readInt(pos + j * 4));
			importLibs.add(lib);
			pos += count * 4;
		}
	}
	
	public void ReadPEImage(byte[] data) throws Exception
	{
		Log.info("XEX Loader: Loading PE Image");
		int len = data.length - offsetPE;
		byte[] compressed;
		compressed = new byte[len];
		for(int i = 0; i < len; i ++)
			compressed[i] = data[offsetPE + i];
		Log.info("XEX Loader: Encryption type = " + baseFileFormat.encryption);
		Log.info("XEX Loader: Compression type = " + baseFileFormat.compression);		
		switch(baseFileFormat.encryption)
		{
			case 0:
				break;
			case 1:
				compressed = Helper.AESDecrypt(sessionKey, compressed);
				break;
			default:
				throw new Exception("Encryption type " + baseFileFormat.encryption + " not supported");
		}
		peImage = new byte[loaderInfo.imageSize];
		int posIn = 0, posOut = 0;
		switch(baseFileFormat.compression)
		{
			case 1:
				for(BaseFileFormat.BasicCompression bc : baseFileFormat.basic)
				{
					for(int i = 0; i < bc.dataSize; i++)
						peImage[i + posOut] = compressed[posIn + i];
					posOut += bc.dataSize + bc.zeroSize;
					posIn += bc.dataSize;
				}
				break;
			case 2:
				BaseFileFormat.NormalCompression nc = baseFileFormat.normal;
				byte[] buff = new byte[nc.blockSize];
				for(int i = 0; i < nc.blockSize; i++)
					buff[i] = compressed[posIn + i];
				posIn += nc.blockSize;
				ByteArrayOutputStream bop = new ByteArrayOutputStream();
				BinaryReader br = new BinaryReader(new ByteArrayProvider(buff), false);
				int nextSize;
				do
				{
					nextSize = br.readInt(0);
					for(int i = 24; i < buff.length;)
					{
						len = br.readShort(i);
						if(len == 0)
							break;
						for(int j = 0; j < len; j++)
							bop.write(buff[i + j + 2]);
						i += 2 + len;
					}
					if(nextSize != 0)
					{
						buff = new byte[nextSize];
						for(int i = 0; i < nextSize; i++)
							buff[i] = compressed[posIn + i];
						posIn += nextSize;
						br = new BinaryReader(new ByteArrayProvider(buff), false);
					}
				}
				while(nextSize != 0);
				byte[] input = bop.toByteArray();
				byte[] output = LZXHelper.Decompress(input);
				for(int i = 0; i < output.length; i++)
					peImage[i + posOut] = output[i];
				break;
			default:
				throw new Exception("Compression type " + baseFileFormat.compression + " not supported");
		}
	}
	
	public void ProcessPData(byte[] data, MemoryBlockUtil mbu, Program program, TaskMonitor monitor) throws Exception	
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		for(int i = 0; i < data.length; i += 8)
		{
			int address = b.readInt(i);
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
			SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, addr, null, "Function_" + String.format("%08X", address), SourceType.ANALYSIS);
		}
		Log.info("XEX Loader: Loaded " + (data.length / 8) + " additional function symbols");
	}
	
	public void ProcessPEImage(MemoryBlockUtil mbu, Program program, TaskMonitor monitor, boolean ProcessPData) throws Exception
	{
		Log.info("XEX Loader: Processing PE Image");
		DOSHeader dos = new DOSHeader(peImage);
		NTHeader nt = new NTHeader(peImage, dos.e_lfanew);
		for(NTHeader.SectionHeader sec : nt.secHeaders)
		{
			int address = sec.VirtualAddress;
			address += imageBaseAddress;
			int size = sec.PhysicalAddressOrVirtualSize;
			Log.info("XEX Loader: Loading section " + sec.Name + " at 0x" + String.format("%08X", address) + " size = 0x" + String.format("%08X", size));			
			byte[] data = new byte[size];
			if( sec.VirtualAddress + size <= peImage.length)
				for(int i = 0; i < size; i++)
					data[i] = peImage[sec.VirtualAddress + i];
			InputStream ds = new ByteArrayInputStream(data);		
			String perm = ""; 
			perm += ((sec.Characteristics & 0x40000000) != 0) ? "1" : "0";
			perm += ((sec.Characteristics & 0x80000000) != 0) ? "1" : "0";
			perm += ((sec.Characteristics & 0x20000000) != 0) ? "1" : "0";
			MakeBlock(mbu, program, sec.Name, sec.Name, address, ds, data.length, perm, monitor);
			if(sec.Name.equals(".pdata") && ProcessPData)
				ProcessPData(data, mbu, program, monitor);
			ds.close();			
		}
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(entryPointAddress);
		program.getSymbolTable().addExternalEntryPoint(addr);
	    program.getSymbolTable().createLabel(addr, "entry", SourceType.ANALYSIS);
	}
	
	public void MakeBlock(MemoryBlockUtil mbu, Program program, String name, String desc, int address, InputStream s, int size, String flgs, TaskMonitor monitor) throws Exception
	{
		byte[] bf = flgs.getBytes();
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
		mbu.createInitializedBlock(name, addr, s, size, desc, desc, bf[0] == '1', bf[1] == '1', bf[2] == '1', monitor);
	}
}
