package sm.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Properties;
import java.util.function.Function;

import sm.SMContainer;

/**
 * This file will write cached files to the disk to be read lated.
 * 
 * @author HardCoded
 */
public final class CacheUtil {
	private static File defaultTracePath;
	private static File cachePath;
	private static File propertiesFile;
	private static Properties properties;
	
	public static File getCachePath() {
		return cachePath;
	}
	
	public static File getTracePath() {
		return new File(getProperty("traces.path", defaultTracePath.getAbsolutePath()));
	}
	
	public static File getDefaultTracePath() {
		return defaultTracePath;
	}
	
	public static String getProperty(String key) {
		return properties.getProperty(key);
	}
	
	public static boolean checkProperty(String path, Object value) {
		return value.toString().equals(getProperty(path));
	}
	
	public static String getProperty(String key, Object def) {
		if(!properties.containsKey(key)) {
			setProperty(key, def);
		}
		
		return properties.getProperty(key);
	}
	
	public static <T> T getProperty(String key, Object def, Function<String,T> obj) {
		if(!properties.containsKey(key)) {
			setProperty(key, def);
		}
		
		return obj.apply(properties.getProperty(key));
	}
	
	public static void setProperty(String key, Object value) {
		properties.setProperty(key, value.toString());
		
		try {
			saveProperties();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void init() throws Exception {
		String userHome = System.getProperty("user.home");
		
		cachePath = new File(userHome, "ScrapMechanicTracer/cache");
		if(!cachePath.exists()) cachePath.mkdirs();
		
		propertiesFile = new File(userHome, "ScrapMechanicTracer/.properties");
		properties = new Properties();
		
		if(!propertiesFile.exists()) {
			propertiesFile.createNewFile();
			saveProperties();
		}
		
		defaultTracePath = new File(userHome, "ScrapMechanicTracer/traces");
		if(!defaultTracePath.exists()) defaultTracePath.mkdirs();
		
		FileInputStream stream = new FileInputStream(propertiesFile);
		properties.load(stream);
		stream.close();
		
		String path = getProperty("traces.path", defaultTracePath.getAbsolutePath());
		
		File tracePath = new File(path);
		if(!tracePath.exists()) {
			System.err.println("The directory '" + path + "' does not exist. Reseting path to default");
			properties.setProperty("traces.path", defaultTracePath.getAbsolutePath());
		}
	}
	
	private static void saveProperties() throws Exception {
		FileOutputStream stream = new FileOutputStream(propertiesFile);
		properties.store(stream, "Saved from CacheUtil.java");
		stream.close();
	}
	
	public static void resetProperties() {
		properties.clear();
		
		try {
			saveProperties();
		} catch(Exception e) {
			e.printStackTrace();
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
