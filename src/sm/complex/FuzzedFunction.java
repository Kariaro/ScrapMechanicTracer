package sm.complex;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import sm.util.LuaUtil;

public class FuzzedFunction implements Serializable {
	private static final long serialVersionUID = 7851898282272717995L;
	
	private Map<Long, HashSet<LuaUtil.Type>> values;
	public int minimumArguments = Integer.MIN_VALUE;
	public int maximumArguments = Integer.MAX_VALUE;
	public List<String> errors;
	
	public FuzzedFunction() {
		errors = new ArrayList<>();
		values = new HashMap<>();
	}
	
	public int getMinimumArguments() {
		return minimumArguments;
	}
	
	public int getMaximumArguments() {
		return maximumArguments;
	}
	
	public void setArgument(long index, String typeName) {
		if(typeName == null) return;
		
		if(values.containsKey(index)) {
			HashSet<LuaUtil.Type> set = values.get(index);
			set.add(LuaUtil.getType(typeName));
			return;
		}
		
		HashSet<LuaUtil.Type> set = new HashSet<>();
		set.add(LuaUtil.getType(typeName));
		values.put(index, set);
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder().append("( ");
		
		long max = Long.MIN_VALUE;
		for(Long index : values.keySet()) {
			if(index > max) max = index;
		}
		
		if(maximumArguments != max && maximumArguments != Integer.MAX_VALUE) {
			max = maximumArguments;
		}
		if(max > 10) max = 10;
		
		{
			for(int i = 1; i <= max; i++) {
				if(i != 1) sb.append(", ");
				
				Set<LuaUtil.Type> types = values.getOrDefault(Long.valueOf(i), null);
				
				//sb.append(i).append(":");
				if(types == null || types.isEmpty()) {
					sb.append("---");
					continue;
				}
				
				if(types.size() == 1) {
					sb.append(types.iterator().next().getPrettyName());
				} else {
					sb.append("[");
					int count = 0;
					for(LuaUtil.Type type : types) {
						if(count++ != 0) sb.append(", ");
						sb.append(type.getPrettyName());
					}
					sb.append("]");
				}
			}
			
			if(max > 0) sb.append(" ");
		}
		
		sb.append(")");
		
		String minArgsStr = (minimumArguments == Integer.MIN_VALUE) ? "???":String.valueOf(minimumArguments);
		String maxArgsStr = (maximumArguments == Integer.MAX_VALUE) ? "???":String.valueOf(maximumArguments);
		if(minArgsStr.equals(maxArgsStr)) {
			if(minArgsStr.equals("???")) {
			} else {
				sb.append(" args:").append(minArgsStr);
			}
		} else {
			sb.append(" min:").append(minArgsStr).append(" ")
			  .append("max:").append(maxArgsStr);
		}
		
		return sb.toString();
	}
	
	public String toStringDebug() {
		StringBuilder sb = new StringBuilder().append(" { ");

		String minArgsStr = (minimumArguments == Integer.MIN_VALUE) ? "???":String.valueOf(minimumArguments);
		String maxArgsStr = (maximumArguments == Integer.MAX_VALUE) ? "???":String.valueOf(maximumArguments);
		if(minArgsStr.equals(maxArgsStr)) {
			sb.append("args:").append(minArgsStr).append(" [\n");
		} else {
			sb.append("min:").append(minArgsStr).append(" ")
			  .append("max:").append(maxArgsStr).append(" [\n");
			
		}
		
		for(Long index : values.keySet()) {
			if(minimumArguments != Integer.MIN_VALUE) {
				if(index < 0) continue;
			}
			
			sb.append(index).append(": ");
			Set<LuaUtil.Type> types = values.get(index);
			for(LuaUtil.Type type : types) {
				sb.append(type).append(", ");
			}
			sb.append("\n");
		}
		
		sb.append("]");
		if(!errors.isEmpty()) {
			sb.append("\n\"Errors\": [\n");
			for(String error : errors) {
				sb.append("    \"").append(error).append("\",\n");
			}
			sb.append("]");
		}
		sb.append("}");
		
		return sb.toString();
	}
}
