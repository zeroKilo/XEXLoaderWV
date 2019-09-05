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
			switch(sec.id)
			{
				case 0x3FF:
					baseFileFormat = new BaseFileFormat(sec.data);				
					break;
				case 0x10100:					
					entryPointAddress = b.readInt(0);
					Log.info("XEX Loader: Entry point address = 0x" + String.format("%08X", entryPointAddress));
					break;
				case 0x10201:
					imageBaseAddress = b.readInt(0);
					Log.info("XEX Loader: Imagebase address = 0x" + String.format("%08X", imageBaseAddress));
					break;
			}
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
		switch(baseFileFormat.encryption)
		{
			case 1:
				compressed = Helper.AESDecrypt(sessionKey, compressed);
				break;
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
				ByteArrayOutputStream bop = new ByteArrayOutputStream();
				BinaryReader br = new BinaryReader(new ByteArrayProvider(buff), false);	
				for(int i = 24; i < buff.length;)
				{
					len = br.readShort(i);
					if(len == 0)
						break;
					for(int j = 0; j < len; j++)
						bop.write(buff[i + j + 2]);
					i += 2 + len;
				}
				byte[] input = bop.toByteArray();
				byte[] output = LZXHelper.Decompress(input);
				for(int i = 0; i < output.length; i++)
					peImage[i + posOut] = output[i];
				break;
		}
	}
	
	public void ProcessPEImage(MemoryBlockUtil mbu, Program program, TaskMonitor monitor) throws Exception
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
			ds.close();			
		}
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(entryPointAddress);
		SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, addr, null, "EntryPoint", SourceType.ANALYSIS);
	}
	
	public void MakeBlock(MemoryBlockUtil mbu, Program program, String name, String desc, int address, InputStream s, int size, String flgs, TaskMonitor monitor)
	{
		try
		{
			byte[] bf = flgs.getBytes();
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
			mbu.createInitializedBlock(name, addr, s, size, desc, desc, bf[0] == '1', bf[1] == '1', bf[2] == '1', monitor);
		}
		catch (Exception e) {
		}
	}
}
