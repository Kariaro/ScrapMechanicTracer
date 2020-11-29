package sm.hardcoded.plugin.json;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class JsonParser {
	public static JsonObject parseFromFile(File file) throws IOException {
		FileInputStream stream = new FileInputStream(file);
		byte[] bytes = stream.readAllBytes();
		stream.close();
		
		return parse(bytes);
	}
	
	public static JsonObject parse(byte[] bytes) {
		return parse(new String(bytes));
	}
	
	public static JsonObject parse(String content) {
		Object object = parse(content.toCharArray(), new int[] { 0 });
		return (JsonObject)object;
	}
	
	private static Object parse(char[] ch, int[] idx) {
		if(!hasNext(ch, idx)) return null;
		eat_spaces(ch, idx);
		
		switch(ch[idx[0]]) {
			case '{': return parseMap(ch, idx);
			case '[': return parseArray(ch, idx);
			case '"': return parseString(ch, idx);
			case 'n': {
				idx[0] += 4;
				eat_spaces(ch, idx);
				return null;
			}
			case 't': {
				idx[0] += 4;
				eat_spaces(ch, idx);
				return Boolean.TRUE;
			}
			case 'f': {
				idx[0] += 5;
				eat_spaces(ch, idx);
				return Boolean.FALSE;
			}
			default: return parseLong(ch, idx);
		}
	}
	
	private static JsonMap parseMap(char[] ch, int[] idx) {
		JsonMap map = new JsonMap();
		
		idx[0]++;
		eat_spaces(ch, idx);
		
		if(!hasNext(ch, idx)) return null;
		if(ch[idx[0]] == '}') {
			idx[0]++;
			eat_spaces(ch, idx);
			return map;
		}
		
		while(hasNext(ch, idx)) {
			eat_spaces(ch, idx);
			String key = parseString(ch, idx);
			if(!hasNext(ch, idx)) break;
			if(ch[idx[0]] != ':') break;
			idx[0]++;
			eat_spaces(ch, idx);
			Object object = parse(ch, idx);
			map.put(key, object);
			
			if(!hasNext(ch, idx)) break;
			char c = ch[idx[0]];
			if(c == '}') {
				idx[0]++;
				break;
			}
			
			if(c == ',') {
				idx[0]++;
				eat_spaces(ch, idx);
				continue;
			}
		}
		
		eat_spaces(ch, idx);
		return map;
	}
	
	private static JsonArray parseArray(char[] ch, int[] idx) {
		JsonArray array = new JsonArray();
		idx[0]++;
		eat_spaces(ch, idx);
		
		if(!hasNext(ch, idx)) return null;
		if(ch[idx[0]] == ']') {
			idx[0]++;
			eat_spaces(ch, idx);
			return array;
		}
		
		eat_spaces(ch, idx);
		while(hasNext(ch, idx)) {
			Object obj = parse(ch, idx);
			array.add(obj);
			
			// Bad should throw exception
			if(!hasNext(ch, idx)) break;
			
			char c = ch[idx[0]];
			if(c == ']') {
				idx[0]++;
				break;
			}
			
			if(c == ',') {
				idx[0]++;
				eat_spaces(ch, idx);
				continue;
			}
		}
		
		eat_spaces(ch, idx);
		return array;
	}
	
	private static String parseString(char[] ch, int[] idx) {
		idx[0]++;
		
		StringBuilder sb = new StringBuilder();
		while(hasNext(ch, idx)) {
			char c = ch[idx[0]++];
			if(c == '"') break;
			sb.append(c);
		}
		
		eat_spaces(ch, idx);
		return sb.toString();
	}
	
	private static Long parseLong(char[] ch, int[] idx) {
		StringBuilder sb = new StringBuilder();
		if(hasNext(ch, idx)) {
			if(ch[idx[0]] == '-') {
				sb.append("-");
				idx[0]++;
			}
		}
		
		while(hasNext(ch, idx)) {
			char c = ch[idx[0]];
			if(!Character.isDigit(c)) break;
			idx[0]++;
			sb.append(c);
		}
		
		eat_spaces(ch, idx);
		try {
			return Long.parseLong(sb.toString());
		} catch(NumberFormatException e) {
			return null;
		}
	}
	
	private static boolean hasNext(char[] ch, int[] idx) {
		if(idx[0] >= ch.length) return false;
		return true;
	}
	
	private static void eat_spaces(char[] ch, int[] idx) {
		while(hasNext(ch, idx)) {
			if(Character.isWhitespace(ch[idx[0]])) {
				idx[0]++;
			} else break;
		}
	}
}
