package sm;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import sm.complex.ScrapMechanic;
import sm.util.LuaReg;
import sm.util.LuaRegList;
import sm.util.Util;

public class SMClassObject implements Serializable {
	private static final long serialVersionUID = 2030879016733772612L;
	
	public List<SMFunctionObject> functions;
	public List<SMConstantObject> constants;
	public List<SMClassObject> classes;
	
	private String base;
	private String path;
	private String name;
	
	public SMClassObject(String path) {
		this(path, null);
	}
	
	public String getName() {
		return name;
	}
	
	public SMClassObject(String path, SMObject object) {
		functions = new ArrayList<>();
		constants = new ArrayList<>();
		classes = new ArrayList<>();
		this.path = path;
		
		if(object != null) {
			loadSettings(object);
			loadFunctions(object);
			loadConstants(object);
		}
	}
	
	public void loadSettings(SMObject obj) {
		base = String.valueOf(obj.getBasePointer());
		path = Util.readTerminatedString(obj.getName());
		name = path.substring(path.lastIndexOf('.') + 1);
	}
	
	public void loadFunctions(SMObject obj) {
		if(obj.hasTabledata()) {
			LuaRegList tabledata = new LuaRegList(obj.getTabledata());
			for(LuaReg ref : tabledata) {
				functions.add(new SMFunctionObject(ref, false));
			}
		}
		
		if(obj.hasUserdata()) {
			LuaRegList userdata = new LuaRegList(obj.getUserdata());
			for(LuaReg ref : userdata) {
				functions.add(new SMFunctionObject(ref, true));
			}
		}
		
		if(obj.hasHidden()) {
			LuaRegList hidden = new LuaRegList(obj.getHidden());
			for(LuaReg ref : hidden) {
				functions.add(new SMFunctionObject(ref, true));
			}
		}
	}
	
	public void loadConstants(SMObject obj) {
		if(!obj.hasConstant()) return;
		
		SMLogger.log("Constants: %s", obj.getConstant());
		// TODO: Implement
	}
	
	protected Set<SMFunctionObject> getAllFunctions() {
		HashSet<SMFunctionObject> set = new HashSet<>();
		for(SMClassObject clazz : classes) {
			set.addAll(clazz.getAllFunctions());
		}
		set.addAll(functions);
		return set;
	}
	
	public boolean hasPath(String path) {
		int index = path.indexOf('.');
		if(index < 0) {
			return false;
		}
		
		return name.equals(path.substring(0, index));
	}
	
	protected SMClassObject addClassFull(String fullPath, String path) {
		path = path.substring(name.length() + 1);
		
		if(path.indexOf('.') != -1) {
			for(SMClassObject clazz : classes) {
				if(clazz.hasPath(path)) {
					return clazz.addClassFull(fullPath, path);
				}
			}
		}
		
		SMClassObject clazz = new SMClassObject(fullPath);
		classes.add(clazz);
		if(path.indexOf('.') > 0) {
			return clazz.addClassFull(fullPath, path);
		}
		
		return clazz;
	}
	
	@Override
	public String toString() {
		return toString("");
	}
	
	protected String toString(String padding) {
		StringBuilder sb = new StringBuilder();
		sb.append(padding);
		if(ScrapMechanic.SHOW_ADDRESS) sb.append(base).append(" -> ");
		sb.append("\"").append(name).append("\": {\n");
		
		int totalValues = constants.size() + classes.size() + functions.size();
		
		for(int i = 0; i < classes.size(); i++) {
			String value = classes.get(i).toString(padding + '\t');
			sb.append(value);
			
			if(totalValues-- > 0) sb.append(",");
			sb.append("\n");
		}
		
		for(int i = 0; i < functions.size(); i++) {
			String value = functions.get(i).toString();
			sb.append(padding).append('\t').append(value);
			
			if(totalValues-- > 0) sb.append(",");
			sb.append("\n");
		}
		
		for(int i = 0; i < constants.size(); i++) {
			String value = constants.get(i).toString();
			sb.append(padding).append('\t').append(value);
			
			if(totalValues-- > 0) sb.append(",");
			sb.append("\n");
		}
		
		sb.append(padding).append("}");
		return sb.toString();
	}
}
