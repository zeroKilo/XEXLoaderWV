package xexloaderwv;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class DOSHeader {
	public short   e_magic;
	public short   e_cblp;
	public short   e_cp;
	public short   e_crlc;
	public short   e_cparhdr;
	public short   e_minalloc;
	public short   e_maxalloc;
	public short   e_ss;
	public short   e_sp;
	public short   e_csum;
	public short   e_ip;
	public short   e_cs;
	public short   e_lfarlc;
	public short   e_ovno;
	public short[] e_res = new short[4];
	public short   e_oemid;
	public short   e_oeminfo;
	public short[] e_res2 = new short[10];
	public int     e_lfanew;
	
	public DOSHeader (byte[] data) throws Exception
	{
		BinaryReader b = new BinaryReader(new ByteArrayProvider(data), true);	
		e_magic = b.readShort(0);
		e_cblp = b.readShort(2);
		e_cp = b.readShort(4);
		e_crlc = b.readShort(6);
		e_cparhdr = b.readShort(8);
		e_minalloc = b.readShort(10);
		e_maxalloc = b.readShort(12);
		e_ss = b.readShort(14);
		e_sp = b.readShort(16);
		e_csum = b.readShort(18);
		e_ip = b.readShort(20);
		e_cs = b.readShort(22);
		e_lfarlc = b.readShort(24);
		e_ovno = b.readShort(26);
		for(int i = 0; i < 4; i++)
			e_res[i] = b.readShort(28 + i * 2);
		e_oemid = b.readShort(36);
		e_oeminfo = b.readShort(38);
		for(int i = 0; i < 10; i++)
			e_res2[i] = b.readShort(40 + i * 2);
		e_lfanew = b.readInt(60);
	}
}
