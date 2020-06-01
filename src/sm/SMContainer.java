package sm;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.mem.MemoryAccessException;
import sm.util.LuaReg;
import sm.util.LuaRegList;
import sm.util.SMUtil;

public class SMContainer implements Serializable {
	private static final long serialVersionUID = 3314121831232541563L;
	protected static final transient String PADDING = "    ";
	protected List<SMClassObject> classes;
	
	public SMContainer() {
		classes = new ArrayList<SMClassObject>();
	}
	
	public static final SMContainer load(String... list) throws MemoryAccessException {
		SMContainer container = new SMContainer();
		
		for(String addr : list) {
			LuaRegList refs = new LuaRegList(addr);
			
			for(LuaReg ref : refs) {
				SMObject obj = SMUtil.loadSMObject(ref);	
				
				container.classes.add(new SMClassObject(obj));
			}
		}
		
		return null;
	}
	
	// TODO: Sort all the names!
	public Set<SMFunctionObject> getAllFunctions() {
		HashSet<SMFunctionObject> set = new HashSet<>();
		for(SMClassObject clazz : classes) {
			set.addAll(clazz.getAllFunctions());
		}
		return set;
	}
	
	public SMClassObject getClass(String path) {
		if(path.startsWith("sm.")) {
			path = path.substring(3);
		}
		
		for(SMClassObject clazz : classes) {
			if(clazz.hasPath(path)) {
				return clazz.getClass(path);
			}
		}
		
		return null;
	}
	
	public SMClassObject addClass(String path) {
		return addClassFull(path, path.substring(3));
	}
	
	protected SMClassObject addClassFull(String fullPath, String path) {
		// System.out.println("SMContainer: addClassFull  \"" + fullPath + "\" -> path = " + path);
		
		for(SMClassObject clazz : classes) {
			if(clazz.hasPath(path)) {
				return clazz.addClassFull(fullPath, path);
			}
		}
		
		SMClassObject clazz = new SMClassObject();
		clazz.setPath(fullPath);
		classes.add(clazz);
		
		return clazz;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		
		sb.append("\"sm\": {\n");
		for(int i = 0; i < classes.size(); i++) {
			String value = classes.get(i).toString(PADDING);
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
