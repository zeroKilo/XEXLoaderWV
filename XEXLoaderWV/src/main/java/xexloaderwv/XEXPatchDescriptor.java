package xexloaderwv;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class XEXPatchDescriptor {
	public int size;
	public int target_version_value;
	public int source_version_value;
	public byte[] digest_source = new byte[0x14];
	public byte[] image_key_source = new byte[0x10];
	public int size_of_target_headers;
	public int delta_headers_source_offset;
	public int delta_headers_source_size;
	public int delta_headers_target_offset;
	public int delta_image_source_offset;
	public int delta_image_source_size;
	public int delta_image_target_offset;
	
	//xex2_delta_patch 
	public int old_addr;
	public int new_addr;
	public short uncompressed_len;
	public short compressed_len;
	public byte[] patch_data;
	
	public XEXPatchDescriptor(byte[] data, int pos)
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);		
		try
		{
			size = b.readInt(pos);
			target_version_value = b.readInt(pos + 4);
			source_version_value = b.readInt(pos + 8);
			pos += 12;
			digest_source = ReadArray(b, pos, 0x14);
			pos += 0x14;
			image_key_source = ReadArray(b, pos, 0x10);
			pos += 0x10;
			size_of_target_headers = b.readInt(pos);
			delta_headers_source_offset = b.readInt(pos + 4);
			delta_headers_source_size = b.readInt(pos + 8);
			delta_headers_target_offset = b.readInt(pos + 12);
			delta_image_source_offset = b.readInt(pos + 16);
			delta_image_source_size = b.readInt(pos + 20);
			delta_image_target_offset = b.readInt(pos + 24);
			pos += 28;
			old_addr = b.readInt(pos);
			new_addr = b.readInt(pos + 4);
			uncompressed_len = b.readShort(pos + 8);
			compressed_len = b.readShort(pos + 10);
			pos += 12;
			patch_data = ReadArray(b, pos, size - 0x58);
		}catch (Exception e) { }
	}
	
	private byte[] ReadArray(BinaryReader b, int pos, int len) throws Exception
	{
		byte[] result = new byte[len];
		for(int i = 0; i < len; i++)
			result[i] = b.readByte(pos + i);
		return result;
	}
}
