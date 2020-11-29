package sm.hardcoded.plugin.exporter;

import java.util.*;

import sm.hardcoded.plugin.json.JsonArray;
import sm.hardcoded.plugin.json.JsonMap;
import sm.hardcoded.plugin.json.JsonObject;
import sm.hardcoded.plugin.tracer.CodeSyntaxTreeAnalyser.TracedFunction;
import sm.hardcoded.plugin.tracer.SMClass;
import sm.hardcoded.plugin.tracer.SMClass.Constant;
import sm.hardcoded.plugin.tracer.SMClass.Function;

public class SmmJsonExporter {
	public static JsonObject convert(JsonObject json, String author, String version, String comment, long time, Map<String, String> urls) {
		SMClass table = JsonExporter.deserialize(json);
		return convert(table, author, version, comment, time, urls);
	}
	
	public static JsonObject convert(JsonObject json) {
		JsonMap map = json.toMap();
		String author = map.getString("author");
		String version = map.getString("version");
		String comment = map.getString("comment");
		long time = map.getLong("time");
		Map<String, String> urls = new HashMap<>();
		{
			JsonMap json_urls = map.getJsonMap("urls");
			for(String key : json_urls.keySet()) {
				urls.put(key, json_urls.getString(key));
			}
		}
		
		SMClass table = JsonExporter.deserialize(json);
		return convert(table, author, version, comment, time, urls);
	}
	
	public static JsonObject convert(SMClass table, String author, String version, String comment, long time, Map<String, String> urls) {
		JsonMap map = new JsonMap();
		map.put("author", author);
		map.put("version", version);
		map.put("comment", comment);
		map.put("time", time);
		
		{
			JsonMap links = new JsonMap();
			map.put("urls", links);
			
			if(urls != null) {
				for(String key : urls.keySet()) {
					links.put(key, urls.get(key));
				}
			}
		}
		
		JsonMap json_map = toJson0(table);
		map.put("content", json_map);
		
		return map;
	}
	
	private static JsonMap toJson0(SMClass table) {
		LinkedList<SMClass> list = new LinkedList<>();
		list.add(table);
		
		JsonMap map = new JsonMap();
		while(!list.isEmpty()) {
			SMClass node = list.poll();
			list.addAll(0, node.getClasses());
			map.put(node.getPath(), toJson(node));
		}
		
		return map;
	}
	
	private static JsonObject toJson(SMClass clazz) {
		JsonMap map = new JsonMap();
		
		List<Constant> constants = clazz.getConstants();
		List<Function> functions = clazz.getFunctions();
		
		JsonMap json_constants = new JsonMap();
		map.put("constants", json_constants);
		for(Constant cons : constants) {
			json_constants.put(cons.getName(), toJson(cons));
		}
		
		JsonMap json_tabledata = new JsonMap();
		map.put("tabledata", json_tabledata);
		for(Function func : functions) {
			if(func.isUserdata()) continue;
			json_tabledata.put(func.getName(), toJson(func));
		}
		
		JsonMap json_userdata = new JsonMap();
		map.put("userdata", json_userdata);
		for(Function func : functions) {
			if(!func.isUserdata()) continue;
			json_userdata.put(func.getName(), toJson(func));
		}
		
		return map;
	}
	
	private static JsonObject toJson(Constant cons) {
		JsonMap map = new JsonMap();
		return map;
	}
	
	private static JsonObject toJson(Function func) {
		JsonMap map = new JsonMap();
		
		TracedFunction trace = func.getTrace();
		Long min_arg = null;
		Long max_arg = null;
		
		if(trace != null) {
			min_arg = trace.getMinArgs();
			max_arg = trace.getMaxArgs();
		}
		
		if(min_arg == max_arg) {
			if(min_arg == null) {
				map.put("args", -1);
			} else {
				map.put("args", min_arg);
			}
		} else {
			JsonMap args = new JsonMap();
			map.put("args", args);
			args.put("min", min_arg == null ? -1:min_arg);
			args.put("max", max_arg == null ? -1:max_arg);
		}
		
		if(trace == null) {
			map.put("sandbox", "");
		} else {
			map.put("sandbox", trace.getSandbox());
		}
		
		JsonArray params = new JsonArray();
		map.put("params", params);
		if(trace != null) {
			if(max_arg == null) {
				for(long i = 1; i < 16; i++) {
					if(trace.getArgument(i) != null) {
						max_arg = i;
					}
				}
			}
			
			if(max_arg != null) {
				for(long min = 1; min <= max_arg; min++) {
					List<String> list = trace.getArgument(min);
					JsonMap param_map = new JsonMap();
					params.add(param_map);
					
					JsonArray types = new JsonArray();
					param_map.put("type", types);
					param_map.put("name", "");
					
					if(list == null) {
						types.add("unknown");
					} else {
						for(String str : list) types.add(str);
					}
				}
			}
		}
		
		{
			JsonArray returns = new JsonArray();
			map.put("returns", returns);
			
			for(String str : trace.getReturnTypes()) {
				returns.add(str);
			}
		}
		
		return map;
	}
}
