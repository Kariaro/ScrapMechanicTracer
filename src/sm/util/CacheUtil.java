package sm.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import sm.SMContainer;

/**
 * This file will write cached files to the disk to be read lated.
 * 
 * @author HardCoded
 */
public class CacheUtil {
	private static File resourcePath;
	private static File cachePath;
	
	public static final File getResourcePath() {
		return resourcePath;
	}
	
	public static final File getCachePath() {
		return cachePath;
	}
	
	public static void init(File path) {
		resourcePath = new File(path, "res");
		cachePath = new File(resourcePath, "cache");
		
		if(!cachePath.exists()) {
			cachePath.mkdirs();
		}
	}
	
	public static SMContainer load(String name) {
		File path = new File(cachePath, name);
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
		File file = new File(cachePath, name);
		return file.exists();
	}
	
	public static boolean save(String name, SMContainer container) {
		try(ObjectOutputStream stream = new ObjectOutputStream(new FileOutputStream(new File(cachePath, name)))) {
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
