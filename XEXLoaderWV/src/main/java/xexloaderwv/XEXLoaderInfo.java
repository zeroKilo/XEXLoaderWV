package xexloaderwv;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class XEXLoaderInfo {
	public int     headerSize;
	public int     imageSize;
	public byte[]  rsaSignature;
	public int     _unknown1;
	public int     imageFlags;
	public int     loadAddress;
	public byte[]  sectionDigest;
	public int     importTableCount;
	public byte[]  importTableDigest;
	public byte[]  mediaId;
	public byte[]  fileKey;
	public int     exportTable;
	public byte[]  headerDigest;
	public int     gameRegions;
	public int     mediaFlags;
	public boolean isDevKit;
	   
	public XEXLoaderInfo(byte[] data, int pos)
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), false);		
		try
		{
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
			
		}catch (Exception e) { }
	}
}
