package xexloaderwv;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class LZXHelper {
	public static Path basefolder;
	
	public static void Init() throws Exception
	{
		basefolder = Files.createTempDirectory("");
		InputStream in = XEXLoaderWVLoader.class.getResourceAsStream("/LZXDecomp.exe");
		byte[] buffer = new byte[1024];
	    int read = -1;
	    File temp = new File(basefolder + "\\LZXDecomp.exe");
	    FileOutputStream fos = new FileOutputStream(temp);
	    while((read = in.read(buffer)) != -1) {
	        fos.write(buffer, 0, read);
	    }
	    fos.close();
	    in.close();
	}
	 
	public static byte[] Decompress(byte[] data) throws Exception
	{
		byte[] result = null;
		CheckAndDelete("output.bin");
		CheckAndDelete("input.bin");
		Files.write(Path.of(basefolder + "\\input.bin"), data);
		Process p = null;
		ProcessBuilder pb = new ProcessBuilder(basefolder + "\\LZXDecomp.exe");
		pb.directory(basefolder.toFile());
		p = pb.start();
		p.waitFor();
		File f = new File(basefolder + "\\output.bin");
		if(f.exists())
		{
			result = Files.readAllBytes(f.toPath());
			CheckAndDelete("output.bin");
		}
		CheckAndDelete("input.bin");
		return result;
	}
	
	public static void CleanUp()
	{
		CheckAndDelete("LZXDecomp.exe");
		CheckAndDelete("input.bin");
		CheckAndDelete("output.bin");
		File f = basefolder.toFile();
		if(f.exists())
			f.delete();
	}
	
	public static void CheckAndDelete(String name)
	{
		File f = new File(basefolder + "\\" + name);
		if(f.exists())
			f.delete(); 
	}
}
