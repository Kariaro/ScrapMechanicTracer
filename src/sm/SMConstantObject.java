package sm;

import java.io.Serializable;
import java.util.HashMap;

import com.google.common.base.Objects;

public class SMConstantObject implements Serializable {
	private static final long serialVersionUID = 2926401670760278882L;
	
	// TODO: Implement
	public HashMap<String, String> values;
	
	public String value;
	public String name;
	
	public SMConstantObject() {
		// TODO: Implement
	}
	
	// TODO: REMOVE
	@Override
	public boolean equals(Object obj) {
		if(obj instanceof SMConstantObject) {
			SMConstantObject constant = (SMConstantObject)obj;
			
			return Objects.equal(name, constant.name)
				&& Objects.equal(value, constant.value);
		}
		return super.equals(obj);
	}
	
	// TODO: REMOVE
	@Override
	public int hashCode() {
		return name.hashCode();
	}
	
	@Override
	public String toString() {
		return new StringBuilder().append("\"").append(name).append("\" = ").append(value).toString();
	}
}
