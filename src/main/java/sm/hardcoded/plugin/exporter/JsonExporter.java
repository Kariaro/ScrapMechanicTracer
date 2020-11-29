package sm.hardcoded.plugin.exporter;

import java.util.LinkedList;
import java.util.List;

import sm.hardcoded.plugin.tracer.CodeSyntaxTreeAnalyser.TracedFunction;
import sm.hardcoded.plugin.tracer.SMClass;
import sm.hardcoded.plugin.tracer.SMClass.Constant;
import sm.hardcoded.plugin.tracer.SMClass.Function;

public class JsonExporter {
	public static SMClass deserialize(JsonObject json) {
		SMClass table = new SMClass("sm");
		
		JsonMap map = json.toMap();
		for(String key : map.keySet()) {
			SMClass clazz = table.createClass(key);
			loadClassFromJson(clazz, map.getJsonMap(key));
		}
		
		return table;
	}
	
	private static void loadClassFromJson(SMClass clazz, JsonMap map) {
		JsonMap constants_map = map.getJsonMap("constants");
		for(String key : constants_map.keySet()) {
			loadConstantFromJson(clazz, key, constants_map.getJsonMap(key));
		}
		
		JsonMap tabledata_map = map.getJsonMap("tabledata");
		for(String key : tabledata_map.keySet()) {
			loadFunctionFromJson(clazz, key, false, tabledata_map.getJsonMap(key));
		}
		
		JsonMap userdata_map = map.getJsonMap("userdata");
		for(String key : userdata_map.keySet()) {
			loadFunctionFromJson(clazz, key, true, userdata_map.getJsonMap(key));
		}
	}
	
	private static void loadConstantFromJson(SMClass clazz, String name, JsonMap map) {
		String address = map.getString("address");
		clazz.createConstant(address, name, "nil");
	}
	
	private static void loadFunctionFromJson(SMClass clazz, String name, boolean local, JsonMap map) {
		// serial
		String address = map.getString("address");
		// hasTrace
		
		Function func = clazz.createFunction(address, name, local);
		
		// Min/Max args
		boolean hasTrace = map.getBoolean("hasTrace");
		if(hasTrace) {
			TracedFunction trace = new TracedFunction();
			func.setTrace(trace);
			
			if(map.isLong("args")) {
				Long args = map.getLong("args");
				trace.setMinimumArgs(args);
				trace.setMaximumArgs(args);
			} else if(map.isMap("args")) {
				JsonMap args = map.getJsonMap("args");
				trace.setMinimumArgs(args.getLong("min"));
				trace.setMaximumArgs(args.getLong("max"));
			}
			
			trace.setSandbox(map.getString("sandbox"));
			
			if(map.isArray("arguments")) {
				JsonArray array = map.getJsonArray("arguments");
				
				for(int i = 0; i < array.getSize(); i++) {
					if(array.isNull(i)) continue;
					else if(array.isString(i)) {
						trace.addType(i + 1, array.getString(i));
					} else if(array.isArray(i)) {
						JsonArray sub_array = array.getJsonArray(i);
						for(int j = 0; j < sub_array.getSize(); j++) {
							trace.addType(i + 1, sub_array.getString(j));
						}
					}
				}
			}
		}
	}
	
	
	public static JsonObject serialize(SMClass table) {
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
	
	public static JsonObject toJson(SMClass clazz) {
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
	
	public static JsonObject toJson(Constant cons) {
		JsonMap map = new JsonMap();
		map.put("address", cons.getAddress());
		return map;
	}
	
	public static JsonObject toJson(Function func) {
		JsonMap map = new JsonMap();
		
		TracedFunction trace = func.getTrace();
		Long min_arg = null;
		Long max_arg = null;
		
		if(trace != null) {
			min_arg = trace.getMinArgs();
			max_arg = trace.getMaxArgs();
		}
		
		map.put("address", func.getAddress());
		map.put("hasTrace", trace != null);
		if(min_arg == max_arg) {
			if(min_arg == null) {
				map.put("args", null);
			} else {
				map.put("args", min_arg);
			}
		} else {
			JsonMap args = new JsonMap();
			map.put("args", args);
			args.put("min", min_arg);
			args.put("max", max_arg);
		}
		
		if(trace == null) {
			map.put("sandbox", null);
		} else {
			map.put("sandbox", trace.getSandbox());
		}
		
		if(trace == null) {
			map.put("arguments", null);
		} else {
			JsonArray array = new JsonArray();
			map.put("arguments", array);
			
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
					
					if(list == null) {
						array.add(null);
					} else if(list.size() == 1) {
						array.add(list.get(0));
					} else {
						JsonArray sub_array = new JsonArray();
						array.add(sub_array);
						for(String str : list) sub_array.add(str);
					}
				}
			}
		}
		
		return map;
	}
}
