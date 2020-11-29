package sm.hardcoded.plugin.exporter;

import java.util.ArrayList;
import java.util.List;

public class JsonArray extends JsonObject {
	private final List<Object> array;
	
	public JsonArray() {
		array = new ArrayList<>();
	}
	
	public JsonObject getJsonObject(int index) {
		return (JsonObject)array.get(index);
	}
	
	public JsonArray getJsonArray(int index) {
		return (JsonArray)array.get(index);
	}
	
	public JsonMap getJsonMap(int index) {
		return (JsonMap)array.get(index);
	}
	
	public Object getObject(int index) {
		return array.get(index);
	}
	
	public String getString(int index) {
		return (String)array.get(index);
	}
	
	public Boolean getBoolean(int index) {
		return (Boolean)array.get(index);
	}
	
	public Long getLong(int index) {
		return (Long)array.get(index);
	}
	
	public boolean isJsonObject(int index) {
		return array.get(index) instanceof JsonObject;
	}
	
	public boolean isArray(int index) {
		return array.get(index) instanceof JsonArray;
	}
	
	public boolean isMap(int index) {
		return array.get(index) instanceof JsonMap;
	}
	
	public boolean isString(int index) {
		return array.get(index) instanceof String;
	}
	
	public boolean isBoolean(int index) {
		return array.get(index) instanceof Boolean;
	}
	
	public boolean isLong(int index) {
		return array.get(index) instanceof Long;
	}
	
	public boolean isNull(int index) {
		return array.get(index) == null;
	}
	
	public boolean isArray() {
		return true;
	}
	
	public boolean isMap() {
		return false;
	}
	
	public void add(Object obj) {
		if(obj instanceof String) {
			array.add(obj);
		} else if(obj instanceof Number) {
			array.add(((Number)obj).longValue());
		} else if(obj instanceof JsonObject) {
			array.add(obj);
		} else if(obj instanceof Boolean) {
			array.add(obj);
		} else if(obj == null) {
			array.add(null);
		}
	}
	
	public void remove(int index) {
		array.remove(index);
	}
	
	public int getSize() {
		return array.size();
	}
	
	public List<Object> copyOf() {
		return List.copyOf(array);
	}
	
	protected String toNormalString() {
		int size = getSize();
		if(size == 0) return "[]";
		
		StringBuilder sb = new StringBuilder();
		sb.append("[\n\t");
		for(int i = 0; i < size; i++) {
			Object obj = array.get(i);
			
			if(obj instanceof String) {
				sb.append("\"").append(obj).append("\"");
			} else if(obj instanceof Long) {
				sb.append(obj);
			} else if(obj instanceof Boolean) {
				sb.append(obj);
			} else if(obj instanceof JsonObject) {
				sb.append(((JsonObject)obj).toString(false).replace("\n", "\n\t"));
			} else if(obj == null) {
				sb.append("null");
			} else {
			}
			
			if(i < size - 1) sb.append(",\n\t");
		}
		
		sb.append("\n]");
		return sb.toString();
	}
	
	protected String toCompactString() {
		int size = getSize();
		if(size == 0) return "[]";
		
		StringBuilder sb = new StringBuilder();
		sb.append("[");
		for(int i = 0; i < size; i++) {
			Object obj = array.get(i);
			
			if(obj instanceof String) {
				sb.append("\"").append(obj).append("\"");
			} else if(obj instanceof Long) {
				sb.append(obj);
			} else if(obj instanceof Boolean) {
				sb.append(obj);
			} else if(obj instanceof JsonObject) {
				sb.append(((JsonObject)obj).toString(true).replace("\n", "\n\t"));
			} else if(obj == null) {
				sb.append("null");
			} else {
			}
			
			if(i < size - 1) sb.append(",");
		}
		
		sb.append("]");
		return sb.toString();
	}
}
