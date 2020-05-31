package sm.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import sm.SMContainer;

public class CacheUtil {
	private static final File CACHE_PATH = new File("C:\\Users\\Admin\\ghidra_scripts\\res\\cache\\");
	
	public static SMContainer load(String name) {
		if(!CACHE_PATH.exists()) CACHE_PATH.mkdirs();
		
		File path = new File(CACHE_PATH, name);
		if(!path.getParentFile().exists()) path.getParentFile().mkdirs();
		if(!path.exists()) return null;
		
		try(ObjectInputStream stream = new ObjectInputStream(new FileInputStream(path))) {
			return (SMContainer)stream.readObject();
		} catch(ClassNotFoundException e) {
			e.printStackTrace();
		} catch(FileNotFoundException e) {
			e.printStackTrace();
		} catch(IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	public static boolean exists(String name) {
		if(!CACHE_PATH.exists()) CACHE_PATH.mkdirs();
		File file = new File(CACHE_PATH, name);
		System.out.println("Exists: ??? " + file.getAbsolutePath());
		return file.exists();
	}
	
	public static boolean save(String name, SMContainer container) {
		if(!CACHE_PATH.exists()) CACHE_PATH.mkdirs();
		
		try(ObjectOutputStream stream = new ObjectOutputStream(new FileOutputStream(new File(CACHE_PATH, name)))) {
			stream.writeObject(container);
			return true;
		} catch(FileNotFoundException e) {
			e.printStackTrace();
		} catch(IOException e) {
			e.printStackTrace();
		}
		
		return false;
	}
}
