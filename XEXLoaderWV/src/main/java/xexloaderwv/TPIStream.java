package xexloaderwv;

import java.util.ArrayList;
import java.util.HashMap;

import org.python.jline.internal.Log;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import xexloaderwv.TypeRecord.BasicTypes;
import xexloaderwv.TypeRecord.LR_Structure;
import xexloaderwv.TypeRecord.MR_Member;

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
	
	
	public TPIStream(byte[] data, TaskMonitor monitor) throws Exception
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
	    monitor.setProgress(0);
		monitor.setMaximum(TypeRecordBytes + 56);
		monitor.setMessage("Processing type records");
	    while(pos - 56 < TypeRecordBytes)
	    {
			if(monitor.isCancelled())
				return;
			monitor.setProgress(pos);
	    	int size = b.readUnsignedShort(pos) - 2;
	    	int kind = b.readUnsignedShort(pos + 2);
	    	byte[] record = b.readByteArray(pos + 4, size);
	    	typeRecords.add(new TypeRecord(typeID, kind, record));
	    	pos += size + 4;
	    	typeID++;
	    }
	    Log.info(String.format("XEX Loader: Processed %d type records", typeRecords.size()));
	}
	
	public void ImportTypeRecords(Program program, TaskMonitor monitor) throws Exception
	{

		long countEnums = 0;
		long countStructures = 0;
		DataTypeManager dtMan = program.getDataTypeManager();
		monitor.setMaximum(typeRecords.size());
		monitor.setMessage("Loading type records");
		long counter = 0;
		HashMap<String, StructureDataType> structMap = new HashMap<String, StructureDataType>();
		for(TypeRecord rec : typeRecords)
		{
			if(monitor.isCancelled())
				return;
			monitor.setProgress(counter++);
			switch(rec.kind)
			{
				case LF_ENUM:
					if(AddEnumType((TypeRecord.LR_Enum)rec.record))
						countEnums++;					
					break;
				case LF_STRUCTURE:
					if(AddStructureType((TypeRecord.LR_Structure)rec.record, structMap))
						countStructures++;					
					break;
				default:
					break;
			}
		}		
		for(TypeRecord rec : typeRecords)
			if(rec.record != null && rec.record.dataType != null)
				dtMan.addDataType(rec.record.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
	    Log.info(String.format("XEX Loader: Imported %d enums, %d structures", countEnums, countStructures));
	}
	
	private boolean AddEnumType(TypeRecord.LR_Enum en)
	{
		for(TypeRecord rec2 : typeRecords)
			if(rec2.typeID == en.field)
			{
				TypeRecord.LR_FieldList fieldList = (TypeRecord.LR_FieldList)rec2.record;
				EnumDataType newEnum = new EnumDataType(en.name, 8);
				for(TypeRecord.MemberRecord m : fieldList.records)
				{
					TypeRecord.MR_Enumerate entry = (TypeRecord.MR_Enumerate)m;
					newEnum.add(entry.name, entry.val.val_long);
				}							
				en.dataType = newEnum;
				return true;
			}
		return false;
	}
	
	private boolean AddStructureType(TypeRecord.LR_Structure str, HashMap<String, StructureDataType> structMap) throws Exception
	{
		try
		{
			StructureDataType newStruct;
			if(structMap.containsKey(str.name))
				newStruct = structMap.get(str.name);
			else
			{
				newStruct = new StructureDataType(str.name, 0);
				newStruct.setPackingEnabled(true);
				structMap.put(str.name, newStruct);
			}
			for(TypeRecord rec : typeRecords)
				if(rec.typeID == str.field)
				{
					TypeRecord.LR_FieldList fieldList = (TypeRecord.LR_FieldList)rec.record;
					for(TypeRecord.MemberRecord mr : fieldList.records)
						switch(mr.recordKind)
						{
							case LF_MEMBER:
								MR_Member member = (MR_Member)mr;
								if(member.index < 0x1000)
								{
									BasicTypes bt = BasicTypes.getByValue(member.index);
									if(!AddBasicTypeToStruct(bt, newStruct, member.name))
										return false;
								}
								else				
								{
									long index = member.index - 0x1000;
									if(index < typeRecords.size())
									{
										TypeRecord target = typeRecords.get((int)index); 
										switch(target.kind)
										{
											case LF_POINTER:
												newStruct.add(new PointerDataType(), member.name, "");
												break;
											case LF_STRUCTURE:
												LR_Structure tstr = (LR_Structure)target.record;
												if(tstr.dataType != null)
													newStruct.add(tstr.dataType, tstr.dataType.getLength(), member.name, "//" + tstr.name);
												else
													return false;
												break;
											default:
												return false;
										}

									}
									else 
										return false;
								}
								break;
							default:				
								return false;
						}
					break;
				}
			newStruct.repack();
			str.dataType = newStruct;
			return true;
		}
		catch (Exception e)
		{
			return false;			
		}
	}	
	
	public boolean AddBasicTypeToStruct(BasicTypes bt, StructureDataType newStruct, String name)
	{
		switch(bt)
		{
			case T_INT8:
			case T_UINT8:
			case T_CHAR:
			case T_UCHAR:
			case T_RCHAR:
			case T_BOOL08:
				newStruct.add(new ByteDataType(), name, "//" + bt.getName());
				break;
			case T_SHORT:
			case T_USHORT:
			case T_WCHAR:
				newStruct.add(new ShortDataType(), name, "//" + bt.getName());
				break;
			case T_INT4:
			case T_UINT4:
			case T_32PVOID:
			case T_LONG:
			case T_ULONG:
			case T_HRESULT:
			case T_32PHRESULT:
			case T_32PBOOL08:
			case T_32PCHAR:
			case T_32PUCHAR:
			case T_32PRCHAR:
			case T_32PWCHAR:
			case T_32PLONG:
			case T_32PULONG:
			case T_32PSHORT:
			case T_32PUSHORT:
			case T_32PREAL32:
			case T_32PREAL64:
			case T_32PINT4:
			case T_32PUINT4:
			case T_32PQUAD:
			case T_32PUQUAD:
				newStruct.add(new IntegerDataType(), name, "//" + bt.getName());
				break;
			case T_QUAD:
			case T_UQUAD:
				newStruct.add(new LongDataType(), name, "//" + bt.getName());
				break;
			case T_REAL32:
				newStruct.add(new FloatDataType(), name, "//" + bt.getName());
				break;
			case T_REAL64:
				newStruct.add(new DoubleDataType(), name, "//" + bt.getName());
				break;
			default:
				Log.info("missed " + bt.getName());
				return false;
		}
		return true;
	}
}
