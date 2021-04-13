package com.hardcoded.plugin.json;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class JsonMap extends JsonObject {
	private final Map<String, Object> map;
	
	public JsonMap() {
		map = new LinkedHashMap<>();
	}
	
	public JsonObject getJsonObject(String key) {
		return (JsonObject)map.get(key);
	}
	
	public JsonArray getJsonArray(String key) {
		return (JsonArray)map.get(key);
	}
	
	public JsonMap getJsonMap(String key) {
		return (JsonMap)map.get(key);
	}
	
	public Object getObject(String key) {
		return map.get(key);
	}
	
	public String getString(String key) {
		return (String)map.get(key);
	}
	
	public Boolean getBoolean(String key) {
		return (Boolean)map.get(key);
	}
	
	public Long getLong(String key) {
		return (Long)map.get(key);
	}
	
	public boolean isJsonObject(String key) {
		return map.get(key) instanceof JsonObject;
	}
	
	public boolean isArray(String key) {
		return map.get(key) instanceof JsonArray;
	}
	
	public boolean isMap(String key) {
		return map.get(key) instanceof JsonMap;
	}
	
	public boolean isString(String key) {
		return map.get(key) instanceof String;
	}
	
	public boolean isBoolean(String key) {
		return map.get(key) instanceof Boolean;
	}
	
	public boolean isLong(String key) {
		return map.get(key) instanceof Long;
	}
	
	public boolean isNull(String key) {
		return map.get(key) == null;
	}
	
	public boolean isArray() {
		return false;
	}
	
	public boolean isMap() {
		return true;
	}
	
	public void put(String key, Object obj) {
		if(obj instanceof String) {
			map.put(key, obj);
		} else if(obj instanceof Number) {
			map.put(key, ((Number)obj).longValue());
		} else if(obj instanceof JsonObject) {
			map.put(key, obj);
		} else if(obj instanceof Boolean) {
			map.put(key, obj);
		} else if(obj == null) {
			map.put(key, null);
		}
	}
	
	public void remove(String key) {
		map.remove(key);
	}
	
	public int getSize() {
		return map.size();
	}
	
	public Set<String> keySet() {
		return map.keySet();
	}
	
	public Map<String, Object> copyOf() {
		return Map.copyOf(map);
	}
	
	protected String toNormalString() {
		int size = getSize();
		if(size == 0) return "{}";
		
		StringBuilder sb = new StringBuilder();
		sb.append("{\n");
		for(String key : map.keySet()) {
			Object obj = map.get(key);
			sb.append("\t\"").append(key).append("\": ");
			
			if(obj instanceof String) {
				sb.append("\"").append(obj).append("\"");
			} else if(obj instanceof Long) {
				sb.append(obj);
			} else if(obj instanceof JsonObject) {
				sb.append(((JsonObject)obj).toString(false).replace("\n", "\n\t"));
			} else if(obj instanceof Boolean) {
				sb.append(obj);
			} else if(obj == null) {
				sb.append("null");
			} else {
			}
			
			sb.append(",\n");
		}
		
		sb.deleteCharAt(sb.length() - 2);
		sb.append("}");
		return sb.toString();
	}
	
	protected String toCompactString() {
		int size = getSize();
		if(size == 0) return "{}";
		
		StringBuilder sb = new StringBuilder();
		sb.append("{");
		for(String key : map.keySet()) {
			Object obj = map.get(key);
			sb.append("\"").append(key).append("\":");
			
			if(obj instanceof String) {
				sb.append("\"").append(obj).append("\"");
			} else if(obj instanceof Long) {
				sb.append(obj);
			} else if(obj instanceof JsonObject) {
				sb.append(((JsonObject)obj).toString(true));
			} else if(obj instanceof Boolean) {
				sb.append(obj);
			} else if(obj == null) {
				sb.append("null");
			} else {
			}
			
			sb.append(",");
		}
		
		sb.deleteCharAt(sb.length() - 1);
		sb.append("}");
		return sb.toString();
	}
}
