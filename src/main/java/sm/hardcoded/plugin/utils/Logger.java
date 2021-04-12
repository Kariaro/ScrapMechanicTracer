package sm.hardcoded.plugin.utils;

import ghidra.util.SystemUtilities;

/**
 * A logger class that's used for debugging this ghidra plugin.
 * 
 * @author HardCoded
 */
public class Logger {
	public static boolean check() {
		return SystemUtilities.isInDevelopmentMode();
	}
	
	public static void print(Object o) {
		if(!check()) return;
		System.out.print(o);
	}
	
	public static void println(Object o) {
		if(!check()) return;
		System.out.println(o);
	}
	
	public static void println() {
		if(!check()) return;
		System.out.println();
	}
	
	public static void printf(String format, Object... args) {
		if(!check()) return;
		System.out.printf(format, args);
	}
	
	public static void log(Throwable t) {
		if(t != null) t.printStackTrace();
	}
}
