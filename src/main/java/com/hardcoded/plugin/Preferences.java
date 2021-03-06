package com.hardcoded.plugin;

import java.io.*;
import java.util.Objects;
import java.util.Properties;

/**
 * Utility class for saving preferences
 *  
 * @author HardCoded
 * @since 0.2.0
 * @date 2020-11-27
 */
public class Preferences {
	private static final String DEFAULT_TRACE_PATH = new File(getSavePath(), "traces").getAbsolutePath();
	private static final int DEFAULT_SEARCH_DEPTH = 1;
	private static final int DEFAULT_NUM_THREADS = 1;
	
	private static final String SEARCH_DEPTH = "search_depth";
	private static final String NUM_THREADS = "num_threads";
	private static final String TRACE_PATH = "trace_path";
	
	public static final String CONFIG_FILE = "config.properties";
	
	private final Properties props = new Properties();
	private String tracePath;
	private int searchDepth;
	private int numThreads;
	
	public Preferences() {
		load();
		
		tracePath = DEFAULT_TRACE_PATH;
		numThreads = DEFAULT_SEARCH_DEPTH;
		searchDepth = DEFAULT_NUM_THREADS;
		
		tracePath = props.getProperty(TRACE_PATH, tracePath);
		setTracePath(tracePath);
		
		try {
			int value = Integer.parseInt(props.getProperty(NUM_THREADS));
			setNumThreads(value);
		} catch(NumberFormatException e) {
			setNumThreads(DEFAULT_NUM_THREADS);
		}
		
		try {
			int value = Integer.parseInt(props.getProperty(SEARCH_DEPTH));
			setSearchDepth(value);
		} catch(NumberFormatException e) {
			setSearchDepth(DEFAULT_SEARCH_DEPTH);
		}
	}
	
	private void load() {
		File file = getConfigFile();
		
		if(!file.exists()) {
			// Make sure we have a properties file to load
			
			try {
				file.createNewFile();
			} catch(IOException e) {
				Logger.log(e);
			}
		}
		
		try(FileInputStream stream = new FileInputStream(file)) {
			props.load(stream);
		} catch(IOException e) {
			Logger.log(e);
		}
	}
	
	private void save() {
		File file = getConfigFile();
		
		try(FileOutputStream stream = new FileOutputStream(file)) {
			props.store(stream, "Generated by the ghidra module ScrapMechanicTracer\nhttps://github.com/Kariaro/ScrapMechanicTracer");
		} catch(IOException e) {
			Logger.log(e);
		}
	}
	
	private void setProperty(String key, Object value) {
		props.setProperty(key, Objects.toString(value, ""));
		save();
	}
	
	public String getTracePath() {
		return tracePath;
	}
	
	public int getSearchDepth() {
		return searchDepth;
	}
	
	public int getNumThreads() {
		return numThreads;
	}
	
	public void setTracePath(String path) {
		setProperty(TRACE_PATH, path);
		tracePath = path;
	}
	
	public void setSearchDepth(int value) {
		if(value < 1 || value > 5) value = DEFAULT_SEARCH_DEPTH;
		setProperty(SEARCH_DEPTH, value);
		searchDepth = value;
	}
	
	public void setNumThreads(int value) {
		if(value < 1 || value > Runtime.getRuntime().availableProcessors()) value = DEFAULT_NUM_THREADS;
		setProperty(NUM_THREADS, value);
		numThreads = value;
	}
	
	public static final File getConfigFile() {
		return new File(getSavePath(), CONFIG_FILE);
	}
	
	public static final File getSavePath() {
		String userHome = System.getProperty("user.home");
		File pluginHome = new File(userHome, ".smtracer");
		if(!pluginHome.exists()) pluginHome.mkdirs();
		return pluginHome;
	}
}
