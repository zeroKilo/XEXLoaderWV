package xexloaderwv;

import java.util.ArrayList;
import java.util.HashMap;

import org.python.jline.internal.Log;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
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
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import xexloaderwv.TypeRecord.BasicTypes;
import xexloaderwv.TypeRecord.LR_Array;
import xexloaderwv.TypeRecord.LR_Bitfield;
import xexloaderwv.TypeRecord.LR_Enum;
import xexloaderwv.TypeRecord.LR_Structure;
import xexloaderwv.TypeRecord.LR_Union;
import xexloaderwv.TypeRecord.LeafRecordKind;
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
    
    
    

	HashMap<String, StructureDataType> structMap;
	HashMap<String, StructureDataType> classMap;
	HashMap<String, UnionDataType> unionMap;
	
	
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
	
	public class FieldMemberEntry
	{
		public long offset;
		public DataType type;
		public String name;
		public String comment;
		public boolean isBitField;
		
		public FieldMemberEntry(long o, DataType t, String n, String c, boolean isB)
		{
			offset = o;
			type = t;
			name = n;
			comment = c;
			isBitField = isB;
		}
	}
	
	public void ImportTypeRecords(Program program, TaskMonitor monitor) throws Exception
	{
		long countEnums = 0;
		long countStructures = 0;
		long countArrays = 0;
		long countUnions = 0;
		long countClasses = 0;
		DataTypeManager dtMan = program.getDataTypeManager();
		monitor.setMaximum(typeRecords.size());
		monitor.setMessage("Loading type records");
		long counter = 0;
		structMap = new HashMap<String, StructureDataType>();
		classMap = new HashMap<String, StructureDataType>();
		unionMap = new HashMap<String, UnionDataType>();
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
					if(AddStructureType((TypeRecord.LR_Structure)rec.record))
						countStructures++;					
					break;
				case LF_ARRAY:
					if(AddArrayType((TypeRecord.LR_Array)rec.record))
						countArrays++;
					break;
				case LF_UNION:
					if(AddUnionType((TypeRecord.LR_Union)rec.record))
						countUnions++;
					break;
				case LF_CLASS:
					if(AddClassType((TypeRecord.LR_Class)rec.record))
						countClasses++;	
					break;
				default:
					break;
			}
		}		
		for(TypeRecord rec : typeRecords)
			if(rec.record != null && rec.record.dataType != null)
				dtMan.addDataType(rec.record.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
	    Log.info(String.format("XEX Loader: Imported %d enums, %d structures, %d arrays, %d unions, %d classes", 
	    						countEnums, 
	    						countStructures, 
	    						countArrays, 
	    						countUnions,
	    						countClasses));
	}
	
	private boolean AddClassType(TypeRecord.LR_Class clazz)
	{
		try
		{
			StructureDataType newClass;
			if(classMap.containsKey(clazz.name))
				newClass = classMap.get(clazz.name);
			else
			{
				newClass = new StructureDataType(clazz.name, 0);
				newClass.setPackingEnabled(true);
				classMap.put(clazz.name, newClass);
			}
			if(clazz.field != 0)
				for(TypeRecord rec : typeRecords)
					if(rec.typeID == clazz.field)
					{
						TypeRecord.LR_FieldList fieldList = (TypeRecord.LR_FieldList)rec.record;
						ArrayList<FieldMemberEntry> entries = GetFieldListMembers(fieldList);
						if(entries == null)
							return false;
						for(FieldMemberEntry e : entries)
							if(!e.isBitField)
								newClass.add(e.type, e.name, e.comment);
							else
								newClass.addBitField(e.type, (int)e.offset, e.name, e.comment);
						break;
					}
			newClass.repack();
			clazz.dataType = newClass;
			return true;
		}
		catch (Exception e)
		{
			return false;			
		}
	}	
	
	private boolean AddUnionType(TypeRecord.LR_Union union)
	{
		try
		{
			UnionDataType newUnion;
			if(unionMap.containsKey(union.name))
				newUnion = unionMap.get(union.name);
			else
			{
				newUnion = new UnionDataType(union.name);
				newUnion.setPackingEnabled(true);
				unionMap.put(union.name, newUnion);
			}
			if(union.field != 0)
				for(TypeRecord rec : typeRecords)
					if(rec.typeID == union.field)
					{
						TypeRecord.LR_FieldList fieldList = (TypeRecord.LR_FieldList)rec.record;
						ArrayList<FieldMemberEntry> entries = GetFieldListMembers(fieldList);
						if(entries == null)
							return false;
						for(FieldMemberEntry e : entries)
							if(!e.isBitField)
								newUnion.add(e.type, e.name, e.comment);
							else
								newUnion.addBitField(e.type, (int)e.offset, e.name, e.comment);
						break;
					}			
			newUnion.repack();
			union.dataType = newUnion;
			return true;
		}
		catch(Exception ex)
		{
			return false;
		}
	}
	
	private boolean AddStructureType(TypeRecord.LR_Structure str)
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
			if(str.field != 0)
				for(TypeRecord rec : typeRecords)
					if(rec.typeID == str.field)
					{
						TypeRecord.LR_FieldList fieldList = (TypeRecord.LR_FieldList)rec.record;
						ArrayList<FieldMemberEntry> entries = GetFieldListMembers(fieldList);
						if(entries == null)
							return false;
						for(FieldMemberEntry e : entries)
							if(!e.isBitField)
								newStruct.add(e.type, e.name, e.comment);
							else
								newStruct.addBitField(e.type, (int)e.offset, e.name, e.comment);
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
	
	private ArrayList<FieldMemberEntry> GetFieldListMembers(TypeRecord.LR_FieldList fieldList)
	{
		try 
		{
			ArrayList<FieldMemberEntry> result = new ArrayList<FieldMemberEntry>();
			for(TypeRecord.MemberRecord mr : fieldList.records)
				switch(mr.recordKind)
				{
					case LF_MEMBER:
						MR_Member member = (MR_Member)mr;
						BinaryReader b = new BinaryReader(new ByteArrayProvider(member.offset.data), true);
						int offset = 0;
						switch(member.offset.type)
						{
							case LF_USHORT:
								offset = b.readUnsignedShort(0);
								break;
							default:
								return null;
						}						
						DataType dt = GetDataTypeByIndex(member.index);
						String name = GetDataTypeNameByIndex(member.index);		
						LeafRecordKind kind = GetTypeKind(member.index);
						if(dt != null && name != null)
							result.add(new FieldMemberEntry(offset, dt, member.name, "//" + name, false));
						else if(kind != null)
						{				
							switch(kind)
							{
								case LF_BITFIELD:
									LR_Bitfield bitfield = (LR_Bitfield)typeRecords.get((int)(member.index - 0x1000)).record;
									dt = GetDataTypeByIndex(bitfield.type);							
									result.add(new FieldMemberEntry(bitfield.length, dt, member.name, "", true));
									break;
								case LF_UNION:
									if(name != null && unionMap.containsKey(name))
									{
										result.add(new FieldMemberEntry(offset, unionMap.get(name), member.name, "//" + name, false));
										break;
									}
									return null;
								default:
									return null;
							}
						}
						else
							return null;
						break;
					default:				
						return null;
				}
			return result;
		}
		catch (Exception e)
		{
			return null;			
		}
	}
	
	private boolean AddArrayType(TypeRecord.LR_Array arr)
	{
		try
		{
			DataType dt = GetDataTypeByIndex(arr.elemtype);
			if(dt != null)
			{
				BinaryReader b = new BinaryReader(new ByteArrayProvider(arr.val.data), true);
				int len = b.readUnsignedShort(0);
				arr.dataType = new ArrayDataType(dt, len, 0);
				return true;
			}
			return false;
		}
		catch (Exception ex)
		{
			return false;
		}
	}
	
	private boolean AddEnumType(TypeRecord.LR_Enum en)
	{
		for(TypeRecord rec : typeRecords)
			if(rec.typeID == en.field)
			{
				TypeRecord.LR_FieldList fieldList = (TypeRecord.LR_FieldList)rec.record;
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
	
	public LeafRecordKind GetTypeKind(long index)
	{
		index -= 0x1000;
		if(index > 0 && index < typeRecords.size())	
			return typeRecords.get((int)index).kind;
		return null;
	}
		
	public DataType GetDataTypeByIndex(long index) throws Exception
	{
		if(index < 0x1000)
			return GetBasicType(BasicTypes.getByValue(index));
		index -= 0x1000;
		if(index > 0 && index < typeRecords.size())
		{
			TypeRecord rec = typeRecords.get((int)index);
			if(rec.record != null)
				switch(rec.kind)
				{
					case LF_POINTER:
						return new PointerDataType();
					case LF_ARRAY:
						return((LR_Array)rec.record).dataType;
					case LF_STRUCTURE:
						return ((LR_Structure)rec.record).dataType;
					case LF_ENUM:
						return ((LR_Enum)rec.record).dataType;
					default:
						index++;
						break;
				}
		}
		return null;
	}
	
	public String GetDataTypeNameByIndex(long index)
	{
		if(index < 0x1000)
			return BasicTypes.getByValue(index).name();
		index -= 0x1000;
		if(index > 0 && index < typeRecords.size())
		{
			TypeRecord rec = typeRecords.get((int)index);
			if(rec.record != null)
				switch(rec.kind)
				{
					case LF_POINTER:
						return "pointer";
					case LF_ARRAY:
						return((LR_Array)rec.record).name;
					case LF_STRUCTURE:
						return ((LR_Structure)rec.record).name;
					case LF_ENUM:
						return ((LR_Enum)rec.record).name;
					case LF_UNION:
						return ((LR_Union)rec.record).name;
					default:
						break;
				}
		}
		return null;
	}
	
	public DataType GetBasicType(BasicTypes bt) throws Exception
	{
		switch(bt)
		{
			case T_INT8:
			case T_UINT8:
			case T_CHAR:
			case T_UCHAR:
			case T_RCHAR:
			case T_BOOL08:
				return new ByteDataType();
			case T_SHORT:
			case T_USHORT:
			case T_WCHAR:
				return new ShortDataType();
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
				return new IntegerDataType();
			case T_QUAD:
			case T_UQUAD:
				return new LongDataType();
			case T_REAL32:
				return new FloatDataType();
			case T_REAL64:
				return new DoubleDataType();
			default:
				throw new Exception("missed basic datatype " + bt.getName());
		}
	}
}
