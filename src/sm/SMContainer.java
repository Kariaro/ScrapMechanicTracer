package sm;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Deprecated(forRemoval = true)
public class SMContainer implements Serializable {
	private static final long serialVersionUID = 3314121831232541563L;
	
	protected List<SMClassObject> classes;
	
	public SMContainer() {
		classes = new ArrayList<>();
	}
	
	public Set<SMFunctionObject> getAllFunctions() {
		Set<SMFunctionObject> set = new HashSet<>();
		
		for(SMClassObject object : classes) {
			set.addAll(object.getAllFunctions());
		}
		
		return set;
	}
	
	/**
	 * This is only used internally.
	 * 
	 * @param path
	 * @return
	 */
	public SMClassObject addClass(String path) {
		return addClassFull(path, path.substring(3));
	}
	
	protected SMClassObject addClassFull(String fullPath, String path) {
		for(SMClassObject clazz : classes) {
			if(clazz.hasPath(path)) {
				return clazz.addClassFull(fullPath, path);
			}
		}
		
		SMClassObject clazz = new SMClassObject(fullPath);
		classes.add(clazz);
		
		return clazz;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		
		sb.append("\"sm\": {\n");
		for(int i = 0; i < classes.size(); i++) {
			String value = classes.get(i).toString("\t");
			sb.append(value);
			
			if(i != classes.size() - 1) {
				sb.append(",");
			}
			
			sb.append("\n");
		}
		sb.append("}");
		
		return sb.toString();
	}
}
