package sm.hardcoded.plugin.tracer;

import ghidra.util.SystemUtilities;

/**
 * A logger class that's used for debugging this ghidra plugin.
 * 
 * @author HardCoded
 */
class Logger {
	static boolean check() {
		return SystemUtilities.isInDevelopmentMode();
	}
	
	static void print(Object o) {
		if(!check()) return;
		System.out.print(o);
	}
	
	static void println(Object o) {
		if(!check()) return;
		System.out.println(o);
	}
	
	static void println() {
		if(!check()) return;
		System.out.println();
	}
	
	static void printf(String format, Object... args) {
		if(!check()) return;
		System.out.printf(format, args);
	}
}
