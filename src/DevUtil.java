import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;


import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class DevUtil {
	private static final File SCRIPT_PATH = new File("C:\\Users\\Admin\\ghidra_scripts\\");
	
	/**
	 * Enable recompilation and usage of multiple files in ghidra.
	 * @throws Exception
	 */
	public static void recompileAllScriptFiles() throws Exception {
		JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
		File bin = new File(SCRIPT_PATH, "bin");
		
		GhidraScriptUtil.USER_SCRIPTS_BIN_DIR = bin.getAbsolutePath();
		GhidraScriptUtil.clean();
		
		if(!bin.exists()) {
			bin.mkdir();
		}
		
		List<String> javaFiles = new ArrayList<>();
		{
			List<File> check = new ArrayList<>();
			check.addAll(Arrays.asList(SCRIPT_PATH.listFiles()));
			do {
				File file = check.get(0);
				check.remove(0);
				
				if(!file.isDirectory()) {
					if(file.getName().endsWith(".java")) {
						javaFiles.add(file.getAbsolutePath());
						if(file.getName().equals("PrintScrapMechanicStructure.java")) {
							BufferedWriter out = new BufferedWriter(new FileWriter(file, true));
							out.write(' ');
							out.close();
							long time = System.currentTimeMillis() + 3000;
							Files.setAttribute(Paths.get(file.toURI()), "lastAccessTime", FileTime.fromMillis(time));
							file.setLastModified(time);
						}
						System.out.println("Loading file: " + file);
					}
				} else {
					String name = file.getName();
					if(name.equals("res") || name.equals("bin")) {
						continue;
					}
					
					check.addAll(Arrays.asList(file.listFiles()));
				}
				
			} while(!check.isEmpty());
		}
		
		compiler.run(null, System.out, System.out, javaFiles.toArray(String[]::new));
		
		{
			List<File> check = new ArrayList<>();
			check.addAll(Arrays.asList(SCRIPT_PATH.listFiles()));
			do {
				File file = check.get(0);
				check.remove(0);
				
				if(!file.isDirectory()) {
					if(file.getName().endsWith(".class")) {
						String curPath = file.getAbsolutePath();
						String newPath = bin.getAbsolutePath() + curPath.substring(SCRIPT_PATH.getAbsolutePath().length());
						System.out.println("Moving file: " + newPath);
						File newFilePath = new File(newPath);
						
						if(newFilePath.getParentFile().exists()) {
							newFilePath.getParentFile().mkdirs();
						}
						
						Files.move(Paths.get(file.toURI()), Paths.get(newFilePath.toURI()), StandardCopyOption.REPLACE_EXISTING);
					}
				} else {
					String name = file.getName();
					if(name.equals("res") || name.equals("bin")) {
						continue;
					}
					
					check.addAll(Arrays.asList(file.listFiles()));
				}
				
			} while(!check.isEmpty());
		}
		
		GhidraScriptUtil.refreshRequested();
		GhidraScriptUtil.refreshDuplicates();
	}
	
	public static GhidraScript runScript(GhidraScript settings, String name) throws Exception {
		File bin = new File(SCRIPT_PATH, "bin");
		
		List<URL> files = new ArrayList<>();
		for(File a : bin.listFiles()) {
			files.add(a.toURI().toURL());
			System.out.println("Loaded: " + a);
		}
		
		ClassLoader loader = URLClassLoader.newInstance(files.toArray(URL[]::new));
		for(Package pcks : loader.getDefinedPackages()) {
			System.out.println("Packages: " + pcks);
		}
		
		GhidraScript created = (GhidraScript)
					loader.loadClass("")
					.getDeclaredConstructor(Program.class, TaskMonitor.class)
					.newInstance(settings.getCurrentProgram(), settings.getMonitor());
		
		
		System.out.println(created);
		return created;
	}

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
