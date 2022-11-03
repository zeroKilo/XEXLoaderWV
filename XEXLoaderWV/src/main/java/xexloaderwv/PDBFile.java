package xexloaderwv;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

import org.python.jline.internal.Log;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import xexloaderwv.TypeRecord.BasicTypes;
import xexloaderwv.TypeRecord.MR_Member;

public class PDBFile {
	
	public class RootStream
	{
		public int size;
		public int[] pages;
	}
	
	public class SymbolRecord
	{   
		public short reclen;
		public short rectyp;
	    public int pubsymflags;
	    public int off;
	    public short seg;
	    public String name;
		public SymbolRecord(ByteArrayProvider input, int pos) throws Exception
		{
			BinaryReader b = new BinaryReader(input, true);
			reclen = (short)(b.readShort(pos) + 2);
			rectyp = b.readShort(pos + 2);
			pubsymflags = b.readInt(pos + 4);
			off = b.readInt(pos + 8);
			seg = b.readShort(pos + 12);
			name = b.readAsciiString(pos + 14);
		}
	}
	
	public int dPageBytes;
	public int dRootBytes;
	public int pAdIndexPages;
	public short symbolStreamIndex;
	public ArrayList<RootStream> rootStreams = new ArrayList<PDBFile.RootStream>();
	public ArrayList<SymbolRecord> symbols = new ArrayList<PDBFile.SymbolRecord>();
	public TPIStream tpi;
	
	public PDBFile(String path, TaskMonitor monitor, Program program) throws Exception
	{
		byte[] data = Files.readAllBytes(Path.of(path));
		ByteArrayProvider bap = new ByteArrayProvider(data);
		BinaryReader b = new BinaryReader(bap, true);
		dPageBytes = b.readInt(0x20);
		dRootBytes = b.readInt(0x2C);
		pAdIndexPages = b.readInt(0x34);
		int pos;
		pos = pAdIndexPages * dPageBytes;
		ArrayList<Integer> pages = new ArrayList<Integer>();
		int count = dRootBytes / dPageBytes;
        if ((dRootBytes / dPageBytes) != 0)
            count++;
		for(int i = 0; i < count; i++)
		{
			int v = b.readInt(pos);
			if(v != 0)
				pages.add(v);
			pos += 4;
		}
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		for(Integer page : pages)
			CopyPage(page, bap, os);
		ReadRootStreams(os.toByteArray());
		ReadDBIData(GetStreamData(3, bap));
		ReadSymbolData(GetStreamData(symbolStreamIndex, bap), monitor);
		ReadTPIData(GetStreamData(2, bap), program, monitor);
		bap.close();
	}
	
	private void CopyPage(int page, ByteArrayProvider input, OutputStream output) throws Exception
	{
		byte[] buff = input.readBytes(page * dPageBytes, dPageBytes);
		output.write(buff);
	}
	
	private byte[] GetStreamData(int index, ByteArrayProvider input) throws Exception
	{
		RootStream rs = rootStreams.get(index);
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		for(Integer page : rs.pages)
			CopyPage(page, input, os);
		return os.toByteArray();
	}
	
	private void ReadDBIData(byte[] data) throws Exception
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
		symbolStreamIndex = b.readShort(0x14);
	}
	
	private void ReadTPIData(byte[] data, Program program, TaskMonitor monitor) throws Exception
	{
		tpi = new TPIStream(data);
		long countEnums = 0;
		long countStructures = 0;
		DataTypeManager dtMan = program.getDataTypeManager();
		monitor.setMaximum(tpi.typeRecords.size());
		monitor.setMessage("Loading type records");
		long counter = 0;
		for(TypeRecord rec : tpi.typeRecords)
		{
			monitor.setProgress(counter++);
			switch(rec.kind)
			{
				case LF_ENUM:
					if(AddEnumType(dtMan, (TypeRecord.LR_Enum)rec.record))
						countEnums++;					
					break;
				case LF_STRUCTURE:
					if(AddStructureType(dtMan, (TypeRecord.LR_Structure)rec.record))
						countStructures++;					
					break;
				default:
					break;
			}
		}
		
	    Log.info(String.format("XEX Loader: Imported %d enums, %d structures", countEnums, countStructures));
	}
	
	private boolean AddEnumType(DataTypeManager dtMan, TypeRecord.LR_Enum en)
	{
		for(TypeRecord rec2 : tpi.typeRecords)
			if(rec2.typeID == en.field)
			{
				TypeRecord.LR_FieldList fieldList = (TypeRecord.LR_FieldList)rec2.record;
				EnumDataType newEnum = new EnumDataType(en.name, 8);
				for(TypeRecord.MemberRecord m : fieldList.records)
				{
					TypeRecord.MR_Enumerate entry = (TypeRecord.MR_Enumerate)m;
					newEnum.add(entry.name, entry.val.val_long);
				}							
				dtMan.addDataType(newEnum, DataTypeConflictHandler.DEFAULT_HANDLER);
				en.dataType = newEnum;
				return true;
			}
		return false;
	}
	
	private boolean AddStructureType(DataTypeManager dtMan, TypeRecord.LR_Structure str) throws Exception
	{
		try
		{
			StructureDataType newStruct = new StructureDataType(str.name, 0);	
			if(str.field >= 0x1000)
				for(TypeRecord rec : tpi.typeRecords)
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
										switch(bt)
										{
											case T_INT8:
											case T_UINT8:
											case T_CHAR:
											case T_UCHAR:
											case T_RCHAR:
											case T_BOOL08:
												newStruct.add(new ByteDataType(), member.name, "//" + bt.getName());
												break;
											case T_SHORT:
											case T_USHORT:
											case T_WCHAR:
												newStruct.add(new ShortDataType(), member.name, "//" + bt.getName());
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
												newStruct.add(new IntegerDataType(), member.name, "//" + bt.getName());
												break;
											case T_QUAD:
											case T_UQUAD:
												newStruct.add(new LongDataType(), member.name, "//" + bt.getName());
												break;
											case T_REAL32:
												newStruct.add(new FloatDataType(), member.name, "//" + bt.getName());
												break;
											case T_REAL64:
												newStruct.add(new DoubleDataType(), member.name, "//" + bt.getName());
												break;
											default:
												Log.info("missed " + bt.getName());
												return false;
										}
									}
									else								
										return false;
									break;
								default:				
									return false;
							}
						break;
					}
			str.dataType = newStruct;
			dtMan.addDataType(newStruct, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
			return true;
		}
		catch (Exception e)
		{
			return false;			
		}
	}
	
	private void ReadSymbolData(byte[] data, TaskMonitor monitor) throws Exception
	{
		ByteArrayProvider bap = new ByteArrayProvider(data);
		int pos = 0;
		monitor.setMaximum(data.length);
		monitor.setMessage("Loading symbol records");
		try
		{
			while(pos < data.length)
			{
				monitor.setProgress(pos);
				SymbolRecord sym = new SymbolRecord(bap, pos);
				pos += sym.reclen;
				symbols.add(sym);
			}
		}
		catch (Exception e){}
		monitor.setProgress(0);
		bap.close();
	}
	
	
	private void ReadRootStreams(byte[] data) throws Exception
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);
		int count = b.readInt(0);
		int pos = 4;
		for(int i = 0; i < count; i++)
		{
			RootStream rs = new RootStream();
			rs.size = b.readInt(pos);
			if(rs.size == -1)
				rs.size = 0;
			rootStreams.add(rs);
			pos += 4;
		}
		for(int i = 0; i < count; i++)
		{
			try
			{
				RootStream rs = rootStreams.get(i);
				int subcount = rs.size / dPageBytes;
	            if ((rs.size % dPageBytes) != 0)
	                subcount++;
	            rs.pages = new int[subcount];
	            for(int j = 0; j < subcount; j++)
	            {
	            	rs.pages[j] = b.readInt(pos);
	            	pos += 4;
	            }
	            rootStreams.set(i,  rs);
			}
			catch(Exception e) {}
		}
	}
}
