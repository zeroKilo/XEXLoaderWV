package xexloaderwv;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class XEXOptionalHeader {

	public int id;
	public int value;
	public byte[] data;
	
	public XEXOptionalHeader(byte[] data, int pos)
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);		
		try
		{
			id = b.readInt(pos);
			value = b.readInt(pos + 4);
		}catch (Exception e) { }
	}
}
