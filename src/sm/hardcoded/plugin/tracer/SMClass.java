package sm.hardcoded.plugin.tracer;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 
 * @author HardCoded
 */
// TODO: Maybe allow to print in alphabetical mode
class SMClass {
	protected Set<SMClass> classes;
	protected Set<Function> functions;
	protected Set<Constant> constants;
	protected String name;
	
	public SMClass(String name) {
		this.name = name;
		
		classes = new LinkedHashSet<>();
		functions = new LinkedHashSet<>();
		constants = new LinkedHashSet<>();
	}
	
	public SMClass getClass(String name) {
		int index = name.indexOf('.');
		String path;
		
		if(index < 0) {
			path = name;
		} else {
			path = name.substring(0, index);
		}
		
		for(SMClass object : classes) {
			if(object.name.equals(path)) {
				return object;
			}
		}
		
		return null;
	}
	
	public SMClass createClass(String name) {
		if(name.startsWith(this.name + '.')) {
			name = name.substring(this.name.length() + 1);
			
			SMClass find = getClass(name);
			
			int index = name.indexOf('.');
			if(index < 0) {
				// "sm.table" -> "table"
				if(find != null) return find;
				
				SMClass klass = new SMClass(name);
				classes.add(klass);
				return klass;
			} else {
				// "sm.table.test" -> "table.test"
				
				SMClass klass;
				if(find != null) {
					klass = find;
				} else {
					klass = new SMClass(name.substring(0, index));
					classes.add(klass);
				}
				
				return klass.createClass(name);
			}
		}
		
		// This should return an error.
		return null;
	}
	
	public Constant createConstant(String address, String name, Object value) {
		Constant constant = new Constant(address, name, value);
		constants.add(constant);
		return constant;
	}
	
	public Function createFunction(String address, String name, boolean local) {
		Function function = new Function(address, name, local);
		functions.add(function);
		return function;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(name).append(" = {");
		int length = constants.size() + classes.size() + functions.size() - 1;
		if(length < 0) {
			return sb.append("}").toString();
		} else {
			sb.append("\n");
		}
		
		for(Constant constant : constants) {
			sb.append('\t').append(constant.toString().replace("\n", "\n\t"));
			if(length-- > 0) sb.append(",");
			sb.append("\n");
		}
		
		for(SMClass klass : classes) {
			sb.append('\t').append(klass.toString().replace("\n", "\n\t"));
			if(length-- > 0) sb.append(",");
			sb.append("\n");
		}
		
		for(Function function : functions) {
			sb.append('\t').append(function);
			if(length-- > 0) sb.append(",");
			sb.append("\n");
		}
		
		return sb.append("}").toString();
	}
	
	static class Constant {
		private final String address;
		private final String name;
		private final String value;
		
		private Constant(String address, String name, Object value) {
			this.address = address;
			this.name = name;
			
			if(value instanceof String) {
				this.value = '"' + value.toString() + '"';
			} else {
				this.value = value == null ? "nil":value.toString();
			}
		}
		
		public String getAddress() {
			return address;
		}
		
		@Override
		public String toString() {
			// TODO: List values
			// TODO: HashMap values
			// constant = {
			//     "a",
			//     "b",
			//     "c",
			//     "d"
			// }
			
			return name + " = " + value;
		}
	}
	
	static class Function {
		private final String address;
		private final String name;
		private final boolean local;
		
		private Integer minArgs;
		private Integer maxArgs;
		
		private Function(String address, String name, boolean local) {
			this.address = address;
			this.name = name;
			this.local = local;
		}
		
		public String getAddress() {
			return address;
		}
		
		public void setArguments(int args) {
			setArguments(args, args);
		}
		
		public void setArguments(int min, int max) {
			if(min < 0) {
				// this is not allowed
				// log that this is not good
			}
			
			minArgs = min;
			maxArgs = max;
			
			// 2048 max stack size.. Anything above that is wrong
		}
		
		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			if(local) sb.append("[userdata] ");
			
			sb.append("function ").append(name).append("(");
			// TODO: Arguments
			sb.append(")");
			
			// TODO: Argument length 'min:4 max:5' 'args:4'
			if(minArgs == null || maxArgs == null) {
				
			}
			
			return sb.toString();
		}
	}

	public Function getFunction(String name) {
		for(Function func : functions) {
			if(func.name.equals(name)) return func;
		}
		
		return null;
	}
}
