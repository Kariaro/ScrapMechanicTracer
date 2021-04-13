package com.hardcoded.plugin;

/**
 * A logger class that's used for debugging this ghidra plugin.
 * 
 * @author HardCoded
 * @since 0.1.0
 */
public class Logger {
	public static boolean check() {
		return System.getProperty("com.hardcoded.devmode") != null;
		// return SystemUtilities.isInDevelopmentMode();
	}
	
	public static void log() {
		if(!check()) return;
		System.out.println();
	}
	
	public static void log(String format, Object... args) {
		if(!check()) return;
		System.out.printf("[" + getCaller() + "]: " + format + "\n", args);
	}
	
	public static void log(Object obj) {
		if(!check()) return;
		System.out.printf("[%s]: %s\n", getCaller(), obj);
	}
	
	public static void log(Throwable t) {
		if(t != null) t.printStackTrace();
	}
	
	private static String getCaller() {
		StackTraceElement[] elements = Thread.getAllStackTraces().get(Thread.currentThread());
		if(elements == null) return "<unknown>";
		return elements[4].getClassName();
	}
}
