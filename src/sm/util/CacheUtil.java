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
public class CacheUtil {
	private static File tracePath;
	private static File cachePath;
	private static File propertiesFile;
	private static Properties properties;
	
	public static final File getCachePath() {
		return cachePath;
	}
	
	public static final File getTracePath() {
		return tracePath;
	}
	
	public static final String getProperty(String key) {
		return properties.getProperty(key);
	}
	
	public static final String getProperty(String key, String def) {
		if(!properties.containsKey(key)) {
			setProperty(key, def);
		}
		
		return properties.getProperty(key);
	}
	
	public static final <T> T getProperty(String key, String def, Function<String,T> obj) {
		if(!properties.containsKey(key)) {
			setProperty(key, def);
		}
		
		return obj.apply(properties.getProperty(key));
	}
	
	public static final void setProperty(String key, Object value) {
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
		
		String path = properties.getProperty(
			"traces.path",
			new File(userHome, "ScrapMechanicTracer/traces").getAbsolutePath()
		);
		
		tracePath = new File(path);//userHome, "ScrapMechanicTracer/traces");
		if(!tracePath.exists()) tracePath.mkdirs();
		
		FileInputStream stream = new FileInputStream(propertiesFile);
		properties.load(stream);
		stream.close();
	}
	
	private static void saveProperties() throws Exception {
		FileOutputStream stream = new FileOutputStream(propertiesFile);
		properties.store(stream, "Saved from CacheUtil.java");
		stream.close();
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
