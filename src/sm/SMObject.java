package sm;

import java.io.Serializable;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import sm.util.Util;

/**
 * This is just a container object for different sm containers.
 * 
 * @author HardCoded
 */
@Deprecated(forRemoval = true)
public class SMObject implements Serializable {
	private static final long serialVersionUID = 744008372035685156L;
	
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
	
	public SMObject(Address address, Function function) {
		basePointerAddress = address.toString();
		loadFunctionAddress = function.getEntryPoint().toString();
	}
	
	public SMObject(Address address, Address function) {
		basePointerAddress = address.toString();
		loadFunctionAddress = function.toString();
	}
	
	public void importRegister(Address name, Address table) {
		nameAddress = name.toString();
		tabledataAddress = table.toString();
	}
	
	public void importUserdata(Address table, Address hidden, Address type) {
		userdataAddress = table.toString();
		hiddenAddress = hidden.toString();
		typeAddress = type.toString();
	}
	
	public void importConstant(Address constant) {
		constantAddress = constant.toString();
	}
	
	/**
	 * @return The function this object belongs to
	 */
	public Function getFunction() {
		return Util.getFunctionAt(loadFunctionAddress);
	}
	
	/**
	 * @return The base pointer for where this object was loaded.
	 */
	public Address getBasePointer() {
		return Util.getAddress(basePointerAddress);
	}
	
	/**
	 * @return Pointer to the userdata {@link SMDataStruct}
	 */
	public Address getUserdata() {
		return Util.getAddress(userdataAddress);
	}
	
	/**
	 * @return Pointer to the hidden userdata functions {@link SMDataStruct}
	 */
	public Address getHidden() {
		return Util.getAddress(hiddenAddress);
	}
	
	/**
	 * @return Pointer to the Type of this object {@link LuaUtil.Type}
	 */
	public Address getType() {
		return Util.getAddress(typeAddress);
	}
	
	/**
	 * @return Pointer to name of this object 
	 */
	public Address getName() {
		return Util.getAddress(nameAddress);
	}
	
	/**
	 * @return Pointer to all the global lua functions {@link SMDataStruct}
	 */
	public Address getTabledata() {
		return Util.getAddress(tabledataAddress);
	}
	
	/**
	 * @return Pointer to the constant functions {@link SMDataStruct}
	 */
	public Address getConstant() {
		return Util.getAddress(constantAddress);
	}
	
	
	public boolean hasUserdata() {
		return userdataAddress != null;
	}
	
	public boolean hasHidden() {
		return hiddenAddress != null;
	}
	
	public boolean hasType() {
		return typeAddress != null;
	}
	
	
	public boolean hasTabledata() {
		return tabledataAddress != null;
	}
	
	public boolean hasName() {
		return nameAddress != null;
	}
	
	
	public boolean hasConstant() {
		return constantAddress != null;
	}
	
	
	@Override
	public String toString() {
		return new StringBuilder()
			.append("SMObject {")
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
