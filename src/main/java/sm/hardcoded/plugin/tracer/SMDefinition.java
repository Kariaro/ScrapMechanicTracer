package sm.hardcoded.plugin.tracer;

import ghidra.program.model.address.Address;

/**
 * This class contains all the information that is used
 * when creating a new element in the global lua table.
 * 
 * @author HardCoded
 * @date 2020-11-27
 */
class SMDefinition {
	// Function address
	private String basePointerAddress;
	private String loadFunctionAddress;
	
	// CreateMetaTable
	private String userdataAddress;
	private String hiddenAddress;
	private String typeAddress;
	
	// luaL_register
	private String tabledataAddress;
	private String nameAddress;
	
	// If the object has a constant
	private String constantAddress;
	
	public SMDefinition(Address basePointer, Address loadFunction) {
		this(getValue(basePointer), getValue(loadFunction));
	}
	
	public SMDefinition(String basePointer, String loadFunction) {
		basePointerAddress = getValue(basePointer);
		loadFunctionAddress = getValue(loadFunction);
	}
	
	public void importRegister(Address name, Address table) { importRegister(getValue(name), getValue(table)); }
	public void importUserdata(Address table, Address hidden, Address type) { importUserdata(getValue(table), getValue(hidden), getValue(type)); }
	public void importConstant(Address constant) { importConstant(getValue(constant)); }
	
	public void importRegister(String name, String table) {
		nameAddress = getValue(name);
		tabledataAddress = getValue(table);
	}
	
	public void importUserdata(String table, String hidden, String type) {
		userdataAddress = getValue(table);
		hiddenAddress = getValue(hidden);
		typeAddress = getValue(type);
	}
	
	public void importConstant(String constant) {
		constantAddress = getValue(constant);
	}
	
	/**
	 * @return The function this definition belongs to
	 */
	public String getFunction() {
		return loadFunctionAddress;
	}
	
	/**
	 * @return The pointer address that points to the define function
	 */
	public String getBasePointer() {
		return basePointerAddress;
	}
	
	/**
	 * @return Pointer to name of this object 
	 */
	public String getName() {
		return nameAddress;
	}
	
	
	/**
	 * @return Pointer to the userdata
	 */
	public String getUserdata() {
		return userdataAddress;
	}
	
	/**
	 * @return Pointer to the hidden userdata functions
	 */
	public String getHidden() {
		return hiddenAddress;
	}
	
	/**
	 * @return Pointer to the defined lua type for this object
	 */
	public String getType() {
		return typeAddress;
	}
	
	/**
	 * @return Pointer to the global lua functions
	 */
	public String getTabledata() {
		return tabledataAddress;
	}
	
	/**
	 * @return Pointer to the constant functions
	 */
	public String getConstant() {
		return constantAddress;
	}
	
	private static final String getValue(Address address) {
		if(address == null) return null;
		return address.toString();
	}
	
	private static final String getValue(String string) {
		if(string == null || string.equals("null")) return null;
		
		try {
			int value = Integer.valueOf(string, 16);
			return String.format("%08x", value);
		} catch(NumberFormatException e) {
			return null;
		}
	}
	
	@Override
	public String toString() {
		return new StringBuilder()
			.append("SMDefinition {")
			.append(" base = ").append(basePointerAddress).append(",")
			.append(" func = ").append(loadFunctionAddress).append(",")
			
			.append(" userdata = ").append(userdataAddress).append(",")
			.append(" hidden = ").append(hiddenAddress).append(",")
			.append(" type = ").append(typeAddress).append(",")
			
			.append(" name = ").append(nameAddress).append(",")
			.append(" table = ").append(tabledataAddress).append(",")
			
			.append(" constant = ").append(constantAddress).append(" ")
			.append("}")
		.toString();	
	}
}
