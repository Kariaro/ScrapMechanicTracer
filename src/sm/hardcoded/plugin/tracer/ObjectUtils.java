package sm.hardcoded.plugin.tracer;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * This class is used to print a java objects content. It will print all private,
 * protected and public fields and return it in a tree type string.
 * 
 * @author HardCoded
 * @since v0.1
 */
public class ObjectUtils {
	private ObjectUtils() {}
	
	public static String deepPrint(Object obj, int depth) throws Exception {
		return deepPrint0("", obj, depth, false);
	}
	
	public static String deepPrint(String name, Object obj, int depth) throws Exception {
		return deepPrint0(name, obj, depth, true);
	}
	
	private static Set<Class<?>> getAllClasses(Class<?> clazz) {
		Set<Class<?>> set = new HashSet<>();
		
		do {
			set.add(clazz);
			clazz = clazz.getSuperclass();
			
			if(clazz == Object.class) break;
		} while(clazz != null);
		
		return set;
	}
	
	private static Set<Field> getAllFields(Class<?> clazz) {
		Set<Field> fields = new HashSet<>();
		for(Class<?> c : getAllClasses(clazz)) {
			fields.addAll(Set.of(c.getDeclaredFields()));
		}
		
		return fields;
	}
	
	private static String deepPrint0(String name, Object obj, int depth, boolean showName) throws Exception {
		if(showName) {
			name += ": ";
		} else {
			name = "";
		}
		
		if(obj == null || depth < 1) {
			try {
				return name + Objects.toString(obj, "null");
			} catch(Exception e) {
				return "null <error>";
			}
		}
		
		Class<?> clazz = obj.getClass();
		String ty = name + clazz.getSimpleName() + " ";
		
		if(clazz == String.class) return ty + "(\"" + (obj.toString()) + "\")";
		if(clazz == Pattern.class) return ty + "(\"" + ((Pattern)obj).pattern() + "\")";
		if(clazz.isEnum() || clazz == Boolean.class || clazz == AtomicInteger.class) return ty + "(" + obj.toString() + ")";
		if(Number.class.isAssignableFrom(clazz)) return ty + "(" + obj.toString() + ")";
		
		if(Collection.class.isAssignableFrom(clazz)) {
			Collection<?> list = (Collection<?>)obj;
			StringBuilder sb = new StringBuilder();
			sb.append(clazz.getSimpleName()).append(" ").append(name).append("\n");
			
			Object[] array = list.toArray();
			for(int i = 0; i < array.length; i++) {
				String string = deepPrint0(Integer.toString(i), array[i], depth - 1, true).trim();
				
				if(showName) {
					sb.append("\t+ ").append(string.replace("\n", "\n\t| "));
				} else {
					sb.append(string);
				}
				
				sb.append("\n");
			}
			
			return sb.toString();
		}
		
		if(clazz.isArray()) {
			StringBuilder sb = new StringBuilder();
			sb.append(name).append("\n");
			
			int len = Array.getLength(obj);
			for(int i = 0; i < len; i++) {
				String string = deepPrint0(Integer.toString(i), Array.get(obj, i), depth - 1, true).trim();
				
				if(showName) {
					sb.append("\t+ ").append(string.replace("\n", "\n\t| "));
				} else {
					sb.append(string);
				}
				
				sb.append("\n");
			}
			
			return sb.toString();
		}
		
		{
			Set<Field> fields = getAllFields(clazz);
			StringBuilder sb = new StringBuilder();
			sb.append(name).append("\n");
			
			for(Field field : fields) {
				if(Modifier.isStatic(field.getModifiers())) continue;
				boolean acc = field.canAccess(obj);
				
				Object value = null;
				if(field.trySetAccessible()) {
					value = field.get(obj);
					field.setAccessible(acc);
				}
				
				String string = deepPrint0(field.getName(), value, depth - 1, true).trim();
				
				if(showName) {
					sb.append("\t+ ").append(string.replace("\n", "\n\t| "));
				} else {
					sb.append(string);
				}
				
				sb.append("\n");
			}
			
			return sb.toString();
		}
	}
}
