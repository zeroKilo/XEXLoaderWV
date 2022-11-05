package xexloaderwv;

import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ghidra.app.util.bin.BinaryReader;

public class Helper {
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static byte[] AESDecrypt(byte[] key, byte[] data) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
		IvParameterSpec iv = new IvParameterSpec(new byte[16]);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
		return cipher.doFinal(data);
	}
	
	public static byte[] ReadArray(BinaryReader b, int pos, int len) throws Exception
	{
		byte[] result = new byte[len];
		for(int i = 0; i < len; i++)
			result[i] = b.readByte(pos + i);
		return result;
	}
	
	public static long forceU32(int input) throws Exception 
	{
	    byte[] bytes = ByteBuffer.allocate(4).putInt(input).array();
	    long value = 
	        ((bytes[3] & 0xFF) <<  0) |
	        ((bytes[2] & 0xFF) <<  8) |
	        ((bytes[1] & 0xFF) << 16) |
	        ((long) (bytes[0] & 0xFF) << 24);
	    return value;
	}
	
	public static int forceU16(short input) throws Exception 
	{
	    byte[] bytes = ByteBuffer.allocate(2).putShort(input).array();
	    int value = ((bytes[1] & 0xFF) <<  0) | ((bytes[0] & 0xFF) <<  8);
	    return value;
	}
	
	public static long GetBits(long buff, int start, int count)
	{
        long result = buff >> start;
        result &= 0xFFFFFFFFl >> 32 - count;
        return result;
	}
	
	public static String ReadCString(BinaryReader b, long pos) throws Exception
	{
		StringBuilder sb = new StringBuilder();
		while(true)
		{
			int c = b.readUnsignedByte(pos++);
			if(c == 0)
				break;
			sb.append((char)c);
		}
		return sb.toString();
	}
}
