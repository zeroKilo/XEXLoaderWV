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
	public XEXDeltaPatch delta_patch;

	public XEXPatchDescriptor(byte[] data, int pos) {
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		try {
			size = b.readInt(pos);
			target_version_value = b.readInt(pos + 4);
			source_version_value = b.readInt(pos + 8);
			pos += 12;
			digest_source = Helper.ReadArray(b, pos, 0x14);
			pos += 0x14;
			image_key_source = Helper.ReadArray(b, pos, 0x10);
			pos += 0x10;
			size_of_target_headers = b.readInt(pos);
			delta_headers_source_offset = b.readInt(pos + 4);
			delta_headers_source_size = b.readInt(pos + 8);
			delta_headers_target_offset = b.readInt(pos + 12);
			delta_image_source_offset = b.readInt(pos + 16);
			delta_image_source_size = b.readInt(pos + 20);
			delta_image_target_offset = b.readInt(pos + 24);
			pos += 28;
			delta_patch = new XEXDeltaPatch(data, pos);
		} catch (Exception e) {
		}
	}
}

class XEXDeltaPatch {
	public int old_addr;
	public int new_addr;
	public int uncompressed_len;
	public int compressed_len;
	public byte[] patch_data;

	public XEXDeltaPatch(byte[] data, int pos) throws Exception {
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		old_addr = b.readInt(pos);
		new_addr = b.readInt(pos + 4);
		uncompressed_len = Helper.forceU16(b.readShort(pos + 8));
		compressed_len = Helper.forceU16(b.readShort(pos + 10));
		patch_data = Helper.ReadArray(b, pos + 12, compressed_len);
	}
}
