package xexloaderwv;

import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class BaseFileFormat {
	public class BasicCompression {
		public int dataSize;
		public int zeroSize;
	}

	public class NormalCompression {
		public int windowSize;
		public int blockSize;
		public byte[] blockHash;
	}

	public short encryption;
	public short compression;
	public ArrayList<BasicCompression> basic;
	public NormalCompression normal;

	public BaseFileFormat(byte[] data) throws Exception {
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		encryption = b.readShort(4);
		compression = b.readShort(6);
		switch (compression) {
		case 1:
			basic = new ArrayList<BaseFileFormat.BasicCompression>();
			int count = (data.length / 8) - 1;
			for (int i = 0; i < count; i++) {
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

class XEXLoaderInfo {
	public int headerSize;
	public int imageSize;
	public byte[] rsaSignature;
	public int _unknown1;
	public int imageFlags;
	public int loadAddress;
	public byte[] sectionDigest;
	public int importTableCount;
	public byte[] importTableDigest;
	public byte[] mediaId;
	public byte[] fileKey;
	public int exportTable;
	public byte[] headerDigest;
	public int gameRegions;
	public int mediaFlags;
	public boolean isDevKit;

	public XEXLoaderInfo(byte[] data, int pos) {
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);
		try {
			headerSize = b.readInt(pos);
			imageSize = b.readInt(pos + 4);
			pos += 8;
			rsaSignature = b.readByteArray(pos, 256);
			pos += 256;
			_unknown1 = b.readInt(pos);
			imageFlags = b.readInt(pos + 4);
			loadAddress = b.readInt(pos + 8);
			pos += 12;
			sectionDigest = b.readByteArray(pos, 20);
			pos += 20;
			importTableCount = b.readInt(pos);
			importTableDigest = b.readByteArray(pos + 4, 20);
			pos += 24;
			mediaId = b.readByteArray(pos, 16);
			pos += 16;
			fileKey = b.readByteArray(pos, 16);
			pos += 16;
			exportTable = b.readInt(pos);
			pos += 4;
			headerDigest = b.readByteArray(pos, 20);
			pos += 20;
			gameRegions = b.readInt(pos);
			mediaFlags = b.readInt(pos + 4);

		} catch (Exception e) {
		}
	}
}