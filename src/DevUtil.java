import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;

import org.apache.commons.lang3.StringUtils;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.ScriptInfo;

public class DevUtil {
	public static File classPath;
	
	public static void replaceGhidraBin(final GhidraScript script) {
		String scriptName = script.toString();
		ScriptInfo info = GhidraScriptUtil.getExistingScriptInfo(scriptName);
		
		if(info == null) {
			// Throw something ?
			return;
		}
		
		// This is going to be the path to the script java file
		// path = "/src/<script>.java"
		ResourceFile file = info.getSourceFile();
		
		// This will trick ghidra into thinking that the script needs to recompile
		{
			long time = System.currentTimeMillis() + 3000;
			try {
				File javaFile = file.getFile(false);
				Files.setAttribute(Paths.get(javaFile.toURI()), "lastAccessTime", FileTime.fromMillis(time));
				javaFile.setLastModified(time);
			} catch(IOException e) {
				e.printStackTrace();
			}
		}
		
		// path = "/"
		ResourceFile path = file.getParentFile().getParentFile();
		classPath = path.getFile(false);
		
		// path = "/bin"
		String binPath = StringUtils.joinWith(File.separator, classPath, "bin");
		GhidraScriptUtil.USER_SCRIPTS_BIN_DIR = binPath;
		GhidraScriptUtil.clean();
		GhidraScriptUtil.refreshRequested();
		GhidraScriptUtil.refreshDuplicates();
	}
	
	/**
	 * This function redirects the standard ouput and error to the ghidra console.
	 * 
	 * @param script
	 */
	public static void replacePrintStreams(final GhidraScript script) {
		System.setOut(new PrintStream(new OutputStream() {
			public void write(String str) {
				script.print(str);
			}
			
			@Override
			public void write(byte[] b, int off, int len) throws IOException {
				write(new String(b, off, len));
			}
			
			@Override
			public void write(byte[] b) throws IOException {
				write(new String(b));
			}
			
			@Override
			public void write(int b) throws IOException {
				write(Character.toString((char)b));
			}
		}));
		
		System.setErr(new PrintStream(new OutputStream() {
			public void write(String str) {
				script.printerr(str);
			}
			
			@Override
			public void write(byte[] b, int off, int len) throws IOException {
				write(new String(b, off, len));
			}
			
			@Override
			public void write(byte[] b) throws IOException {
				write(new String(b));
			}
			
			@Override
			public void write(int b) throws IOException {
				write(Character.toString((char)b));
			}
		}));
	}
}
