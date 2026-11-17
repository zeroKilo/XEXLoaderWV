package xexloaderwv;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class XEXOptionalHeader {

	public int id;
	public int value;
	public byte[] data;

	public XEXOptionalHeader(byte[] data, int pos) {
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		try {
			id = b.readInt(pos);
			value = b.readInt(pos + 4);
		} catch (Exception e) {
		}
	}
}

class XEXSection {
	public byte type;
	public int pageCount;
	public byte[] digest;

	public XEXSection(byte[] data, int pos) throws Exception {
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		int temp = b.readInt(pos);
		type = (byte) (temp & 0xF);
		pageCount = temp >> 4;
		digest = b.readByteArray(pos + 4, 20);
	}
}
