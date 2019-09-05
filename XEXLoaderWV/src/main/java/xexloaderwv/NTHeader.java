package xexloaderwv;

import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class NTHeader {	
	public int magic;
	public ImageFileHeader imgHeader;
	public ImageOptionalHeader optHeader;
	public ArrayList<SectionHeader> secHeaders = new ArrayList<NTHeader.SectionHeader>();
	public NTHeader (byte[] data, int pos) throws Exception
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
		magic = b.readInt(pos);
		imgHeader = new ImageFileHeader(data, pos + 4);
		optHeader = new ImageOptionalHeader(data, pos + 24);
		int secPos = pos + imgHeader.sizeOfOptionalHeader + 24;
		for(int i = 0; i < imgHeader.numberOfSections; i++)
		{
			secHeaders.add(new SectionHeader(data, secPos));
			secPos += 40;
		}
	}
	
	public class SectionHeader
	{
		public String	Name;
		public int		PhysicalAddressOrVirtualSize;
		public int		VirtualAddress;
		public int		SizeOfRawData;
		public int		PointerToRawData;
		public int		PointerToRelocations;
		public int		PointerToLinenumbers;
		public short	NumberOfRelocations;
		public short	NumberOfLinenumbers;
		public int		Characteristics;
		public SectionHeader(byte[] data, int pos) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			Name = "";
			for(int i = 0; i < 8; i++)
				if(data[pos + i] != 0)
					Name += (char)data[pos + i];
				else
					break;
			PhysicalAddressOrVirtualSize = b.readInt(pos + 8);
			VirtualAddress = b.readInt(pos + 12);
			SizeOfRawData = b.readInt(pos + 16);
			PointerToRawData = b.readInt(pos + 20);
			PointerToRelocations = b.readInt(pos + 24);
			PointerToLinenumbers = b.readInt(pos + 28);
			NumberOfRelocations = b.readShort(pos + 32);
			NumberOfLinenumbers = b.readShort(pos + 34);
			Characteristics = b.readInt(pos + 36);
		}
	}

	public class ImageFileHeader
	{
		public short	machine;
		public short	numberOfSections;
		public int		timeDateStamp;
		public int		pointerToSymbolTable;
		public int		numberOfSymbols;
		public short	sizeOfOptionalHeader;
		public short	characteristics;
		public ImageFileHeader(byte[] data, int pos) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			machine = b.readShort(pos);
			numberOfSections = b.readShort(pos + 2);
			timeDateStamp = b.readInt(pos + 4);
			pointerToSymbolTable = b.readInt(pos + 8);
			numberOfSymbols = b.readInt(pos + 12);
			sizeOfOptionalHeader = b.readShort(pos + 16);
			characteristics = b.readShort(pos + 18);
		}
	}
	
	public class ImageOptionalHeader
	{
		public class ImageDataDirectory
		{
			public int virtualAddress;
			public int size;
			public ImageDataDirectory(byte[] data, int pos) throws Exception
			{
				BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
				virtualAddress = b.readInt(pos);
				size = b.readInt(pos + 4);
			}
		}
		
				
		public short	Magic;
		public byte		MajorLinkerVersion;
		public byte		MinorLinkerVersion;
		public int		SizeOfCode;
		public int		SizeOfInitializedData;
		public int		SizeOfUninitializedData;
		public int		AddressOfEntryPoint;
		public int		BaseOfCode;
		public int		BaseOfData;
		public int		ImageBase;
		public int		SectionAlignment;
		public int		FileAlignment;
		public short	MajorOperatingSystemVersion;
		public short	MinorOperatingSystemVersion;
		public short	MajorImageVersion;
		public short	MinorImageVersion;
		public short	MajorSubsystemVersion;
		public short	MinorSubsystemVersion;
		public int		Win32VersionValue;
		public int		SizeOfImage;
		public int		SizeOfHeaders;
		public int		CheckSum;
		public short	Subsystem;
		public short	DllCharacteristics;
		public int		SizeOfStackReserve;
		public int		SizeOfStackCommit;
		public int		SizeOfHeapReserve;
		public int		SizeOfHeapCommit;
		public int		LoaderFlags;
		public int		NumberOfRvaAndSizes;
		public ArrayList<ImageDataDirectory> dataDirectories = new ArrayList<ImageDataDirectory>();
		public ImageOptionalHeader(byte[] data, int pos) throws Exception
		{
			BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
			Magic = b.readShort(pos);
			MajorLinkerVersion = data[pos + 2];
			MinorLinkerVersion = data[pos + 3];
			SizeOfCode = b.readInt(pos + 4);
			SizeOfInitializedData = b.readInt(pos + 8);
			SizeOfUninitializedData = b.readInt(pos + 12);
			AddressOfEntryPoint = b.readInt(pos + 16);
			BaseOfCode = b.readInt(pos + 20);
			BaseOfData = b.readInt(pos + 24);
			ImageBase = b.readInt(pos + 28);
			SectionAlignment = b.readInt(pos + 32);
			FileAlignment = b.readInt(pos + 36);
			MajorOperatingSystemVersion = b.readShort(pos + 40);
			MinorOperatingSystemVersion = b.readShort(pos + 42);
			MajorImageVersion = b.readShort(pos + 44);
			MinorImageVersion = b.readShort(pos + 46);
			MajorSubsystemVersion = b.readShort(pos + 48);
			MinorSubsystemVersion = b.readShort(pos + 50);
			Win32VersionValue = b.readInt(pos + 52);
			SizeOfImage = b.readInt(pos + 56);
			SizeOfHeaders = b.readInt(pos + 60);
			CheckSum = b.readInt(pos + 64);
			Subsystem = b.readShort(pos + 68);
			DllCharacteristics = b.readShort(pos + 70);
			SizeOfStackReserve = b.readInt(pos + 72);
			SizeOfStackCommit = b.readInt(pos + 76);
			SizeOfHeapReserve = b.readInt(pos + 80);
			SizeOfHeapCommit = b.readInt(pos + 84);
			LoaderFlags = b.readInt(pos + 88);
			NumberOfRvaAndSizes = b.readInt(pos + 92);
			for(int i = 0; i < NumberOfRvaAndSizes; i++)
				dataDirectories.add(new ImageDataDirectory(data, pos + i * 8 + 96));
		}
	}
}
