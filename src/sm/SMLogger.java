package sm;

public class SMLogger {
	public static void log() {
		System.out.println();
	}
	
	public static void log(String format, Object... args) {
		System.out.printf(format + "\n", args);
	}
	
	public static void err(String format, Object... args) {
		System.err.printf(format + "\n", args);
	}
}
