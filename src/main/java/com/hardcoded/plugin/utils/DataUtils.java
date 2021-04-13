package com.hardcoded.plugin.utils;

/**
 * A utility file to convert byte arrays into primitive types
 * 
 * @author HardCoded
 * @since 0.1.0
 */
public final class DataUtils {
	private static final boolean BIG_ENDIAN = true;
	
	private DataUtils() {
		
	}
	
	private static long read_number(byte[] bytes, int length, int offset) {
		long result = 0;
		
		if(BIG_ENDIAN) {
			for(int i = 0; i < length; i++) {
				result |= ((bytes[i] & 0xffL) << (8L * i));
			}
		} else {
			for(int i = 0; i < length; i++) {
				result |= ((bytes[i] & 0xffL) << (8L * (length - i)));
			}
		}
		
		return result;
	}
	
	public static double getDouble(byte[] bytes, int offset) {
		return Double.longBitsToDouble(read_number(bytes, 8, offset));
	}
	
	public static double getFloat(byte[] bytes, int offset) {
		return Float.intBitsToFloat((int)read_number(bytes, 4, offset));
	}
	
	public static long getLong(byte[] bytes, int offset) {
		return read_number(bytes, 8, offset);
	}
	
	public static int getInt(byte[] bytes, int offset) {
		return (int)read_number(bytes, 4, offset);
	}
	
	public static int getShort(byte[] bytes, int offset) {
		return (short)read_number(bytes, 2, offset);
	}
	
	public static long getInteger(byte[] bytes, int length, int offset) {
		return read_number(bytes, length, offset);
	}
	
	public static String toHex(long value, boolean reverse) {
		if(reverse) {
			return String.format("%02x%02x%02x%02x%02x%02x%02x%02x",
				(value << 56L) & 0xffL,
				(value << 48L) & 0xffL,
				(value << 40L) & 0xffL,
				(value << 32L) & 0xffL,
				(value << 24L) & 0xffL,
				(value << 16L) & 0xffL,
				(value <<  8L) & 0xffL,
				(value       ) & 0xffL
			);
		}
		
		return String.format("%016x", value);
	}
}
