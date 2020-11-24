package sm.hardcoded.plugin.tracer;

import java.util.*;

import sm.hardcoded.plugin.tracer.CodeSyntaxTreeUtils.TracedFunction;

/**
 * A class object for all sm objects.
 * 
 * @date 2020-11-24
 * @author HardCoded
 */
class SMClass {
	protected List<SMClass> classes;
	protected List<Function> functions;
	protected List<Constant> constants;
	protected String name;
	
	public SMClass(String name) {
		this.name = name;
		
		classes = new ArrayList<>();
		functions = new ArrayList<>();
		constants = new ArrayList<>();
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
				if(find != null) return find;
				
				SMClass clazz = new SMClass(name);
				classes.add(clazz);
				return clazz;
			} else {
				SMClass clazz;
				if(find != null) {
					clazz = find;
				} else {
					clazz = new SMClass(name.substring(0, index));
					classes.add(clazz);
				}
				
				return clazz.createClass(name);
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
		private TracedFunction trace;
		
		private Function(String address, String name, boolean local) {
			this.address = address;
			this.name = name;
			this.local = local;
		}
		
		public String getAddress() {
			return address;
		}
		
		public String getName() {
			return name;
		}
		
		public TracedFunction getTrace() {
			return trace;
		}
		
		public int hashCode() {
			return address.hashCode();
		}
		
		public boolean equals(Object obj) {
			if(!(obj instanceof Function)) return false;
			return hashCode() == obj.hashCode();
		}
		
		public void setTrace(TracedFunction trace) {
			this.trace = trace;
		}
		
		public String toString() {
			StringBuilder sb = new StringBuilder();
			if(local) sb.append("[userdata] ");
			
			if(trace != null) {
				if(!trace.getSandbox().isEmpty()) {
					sb.append("[").append(trace.getSandbox()).append("] ");
				}
			}
			
			sb.append("function ").append(name);
			
			if(trace == null) {
				sb.append("() <no trace>");
			} else {
				String args = trace.getArgumentString();
				if(args.isEmpty()) {
					sb.append("() ");
				} else {
					sb.append("( ").append(args).append(" ) ");
				}
				
				sb.append(trace.getSizeString());
			}
			
			return sb.toString();
		}
	}
	
	public List<Function> getAllFunctions() {
		List<Function> set = new ArrayList<>();
		set.addAll(functions);
		for(SMClass clazz : classes) {
			set.addAll(clazz.getAllFunctions());
		}
		
		return set;
	}
	
	public Function getFunction(String name) {
		for(Function func : functions) {
			if(func.name.equals(name)) return func;
		}
		
		return null;
	}
}
