package sm;

import java.io.Serializable;
import java.util.HashMap;

public class SMConstantObject implements Serializable {
	private static final long serialVersionUID = 2926401670760278882L;
	
	public HashMap<String, String> values;
	
	public String value;
	public String name;
	
	public SMConstantObject() {
		// TODO: Implement
	}
	
	@Override
	public String toString() {
		return new StringBuilder().append("\"").append(name).append("\" = ").append(value).toString();
	}
}
