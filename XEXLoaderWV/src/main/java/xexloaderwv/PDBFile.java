package xexloaderwv;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

import org.python.jline.internal.Log;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

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
		tpi = new TPIStream(data, monitor);
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
				if(monitor.isCancelled())
					return;
				monitor.setProgress(pos);
				SymbolRecord sym = new SymbolRecord(bap, pos);
				pos += sym.reclen;
				symbols.add(sym);
			}
		}
		catch (Exception e){}
		monitor.setProgress(0);
		bap.close();
	    Log.info(String.format("XEX Loader: Processed %d symbols", symbols.size()));
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
