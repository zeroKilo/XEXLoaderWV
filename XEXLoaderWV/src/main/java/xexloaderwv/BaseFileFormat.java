package xexloaderwv;

import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class BaseFileFormat {
	public class BasicCompression
	{
		public int dataSize;
		public int zeroSize;
	}
	
	public class NormalCompression
	{
		public int windowSize;
		public int blockSize;
		public byte[] blockHash;
	}
	
	public short encryption;
	public short compression;
	public ArrayList<BasicCompression> basic;
	public NormalCompression normal;
	
	public BaseFileFormat(byte[] data) throws Exception
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		encryption = b.readShort(4);
		compression = b.readShort(6);
		switch(compression)
		{
			case 1:
				basic = new ArrayList<BaseFileFormat.BasicCompression>();
				int count = (data.length / 8) - 1;
				for(int i = 0; i < count; i++)
				{
					BasicCompression bc = new BasicCompression();
					bc.dataSize = b.readInt(0x8 + i * 8);
					bc.zeroSize = b.readInt(0xC + i * 8);
					basic.add(bc);
				}
				break;
			case 2:
			case 3:
				normal = new NormalCompression();
				normal.windowSize = b.readInt(0x8);
				normal.blockSize = b.readInt(0xC);
				normal.blockHash = b.readByteArray(0x10, 20);
				break;
		}
	}
}
