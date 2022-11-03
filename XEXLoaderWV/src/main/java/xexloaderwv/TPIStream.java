package xexloaderwv;

import java.util.ArrayList;

import org.python.jline.internal.Log;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class TPIStream {

	public enum TPIVersion
    {
        V40 ("V40", 19950410), //0x01306B4A
        V41 ("V41", 19951122), //0x01306E12
        V50 ("V50", 19961031), //0x013094C7
        V70 ("V70", 19990903), //0x01310977
        V80 ("V80", 20040203); //0x0131CA0B
        private final String name;
        private final long value;
        private TPIVersion(String name, long value) { this.name = name; this.value = value; } 
        public String getName() { return name; }
        public long getValue() { return value; }
        public static TPIVersion getByValue(long l)
        {
        	for(TPIVersion v : TPIVersion.values())
        		if(v.value == l)
        			return v;
        	return null;
        }
    }
    public TPIVersion Version;
    public long HeaderSize;
    public long TypeIndexBegin;
    public long TypeIndexEnd;
    public long TypeRecordBytes;
    public int HashStreamIndex;
    public int HashAuxStreamIndex;
    public long HashKeySize;
    public long NumHashBuckets;
    public long HashValueBufferOffset;
    public long HashValueBufferLength;
    public long IndexOffsetBufferOffset;
    public long IndexOffsetBufferLength;
    public long HashAdjBufferOffset;
    public long HashAdjBufferLength;
    public ArrayList<TypeRecord> typeRecords;
	
	
	public TPIStream(byte[] data) throws Exception
	{		
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
		Version = TPIVersion.getByValue(b.readUnsignedInt(0));
		if(Version == TPIVersion.V40)
			return;
	    HeaderSize = b.readUnsignedInt(4);
	    TypeIndexBegin = b.readUnsignedInt(8);
	    TypeIndexEnd = b.readUnsignedInt(12);
	    TypeRecordBytes = b.readUnsignedInt(16);
	    HashStreamIndex = b.readUnsignedShort(20);
	    HashAuxStreamIndex = b.readUnsignedShort(22);
	    HashKeySize = b.readUnsignedInt(24);
	    NumHashBuckets = b.readUnsignedInt(28);
	    HashValueBufferOffset = b.readUnsignedInt(32);
	    HashValueBufferLength = b.readUnsignedInt(36);
	    IndexOffsetBufferOffset = b.readUnsignedInt(40);
	    IndexOffsetBufferLength = b.readUnsignedInt(44);
	    HashAdjBufferOffset = b.readUnsignedInt(48);
	    HashAdjBufferLength = b.readUnsignedInt(52);
	    typeRecords = new ArrayList<TypeRecord>();
	    long pos = 56;
	    long typeID = 0x1000;
	    while(pos - 56 < TypeRecordBytes)
	    {
	    	int size = b.readUnsignedShort(pos) - 2;
	    	int kind = b.readUnsignedShort(pos + 2);
	    	byte[] record = b.readByteArray(pos + 4, size);
	    	typeRecords.add(new TypeRecord(typeID, kind, record));
	    	pos += size + 4;
	    	typeID++;
	    }
	    Log.info(String.format("XEX Loader: Processed %d type records", typeRecords.size()));
	}
}
