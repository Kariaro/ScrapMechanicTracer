package sm.hardcoded.plugin.tracer;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import sm.hardcoded.plugin.tracer.ScrapMechanicBookmarkManager.BookmarkCategory;

class TableElementFinder {
	private final ScrapMechanicPlugin plugin;
	private final ScrapMechanicBookmarkManager manager;
	
	TableElementFinder(ScrapMechanicPlugin tool) {
		plugin = tool;
		manager = tool.getBookmarkManager();
	}
	
	public SMDefinition findSMObject(FunctionPointer func) {
		Program program = plugin.getCurrentProgram();
		
		// The program should not have been analyzed here so there is no worry that we do stuff that we do not need to do.
		// DissasemblerPlugin:216 - StaticDissasemble.
		
		DisassembleCommand cmd = new DisassembleCommand(func.entry, null, true);
		cmd.enableCodeAnalysis(false);
		if(!cmd.applyTo(program)) {
			Msg.warn(this, "Failed to disassemble memory at address '" + func.entry + "'");
		}
		
		Instruction iter = program.getListing().getInstructionAt(func.entry);
		
		SMDefinition object = new SMDefinition(func.location, func.entry);
		List<Instruction> list = new ArrayList<>();
		
		String push_find = null;
		do {
			iter = iter.getNext();
			
			String mnemonic = iter.getMnemonicString();
			switch(mnemonic) {
				case "RET": {
					iter = null;
					continue;
				}
				
				case "PUSH": {
					list.add(iter);
					
					if(push_find != null) {
						String check = getAddress(iter, 0);
						
						if(push_find.equals(check)) {
							// Msg.debug(this, String.format("    : CreateConstant( constant = %s )", list.get(0).getAddress(0)));
							object.importConstant(getAddress(list.get(0), 0));
						}
					}
					
					continue;
				}
				case "CALL": {
					if(list.size() >= 3) {
						int size = list.size();
						String addr_0 = getAddress(list.get(size - 3), 0);
						String addr_1 = getAddress(list.get(size - 2), 0);
						String addr_2 = getAddress(list.get(size - 1), 0);
						
						if(addr_2 == null) {
							// Msg.debug(this, String.format("    : luaL_register( table = %s, name = %s )", addr_0, addr_1));
							object.importRegister(addr_1, addr_0);
							
							push_find = addr_1;
						} else {
							// Msg.debug(this, String.format("    : CreateUserdata( table = %s, userdata = %s, type = %s )", addr_0, addr_1, addr_2));
							object.importUserdata(addr_0, addr_1, addr_2);
							
							// LuaTypes.INSTANCE.addType(plugin, addr_2);
						}
					}
					
					list.clear();
				}
			}
		} while(iter != null);
		
		return object;
	}
	
	public String getAddress(Instruction i, int index) {
		String string = i.getDefaultOperandRepresentation(index);
		if(string.startsWith("0x")) string = string.substring(2);
		
		try {
			int value = Integer.valueOf(string, 16);
			return String.format("%08x", value);
		} catch(NumberFormatException e) {
			return null;
		}
	}

	public List<SMDefinition> findSMObjects(List<FunctionPointer> tables) {
		List<SMDefinition> list = new ArrayList<>();
		List<Bookmark> bookmarks = manager.getBookmarks(BookmarkCategory.TABLE_ELEMENT);
		
		long time = System.currentTimeMillis();
		if(!bookmarks.isEmpty()) {
			plugin.getWindow().writeLog(this, "Reading SMObjects from cache");
			
			for(Bookmark bookmark : bookmarks) {
				Address entry = bookmark.getAddress();
				
				for(int i = 0; i < tables.size(); i++) {
					FunctionPointer func = tables.get(i);
					
					if(entry.toString().equals(func.entry.toString())) {
						String[] parts = bookmark.getComment().split(", ");
						
						SMDefinition object = new SMDefinition(func.location, func.entry);
						object.importConstant(parts[0]);
						object.importRegister(parts[1], parts[2]);
						object.importUserdata(parts[3], parts[4], parts[5]);
						list.add(object);
						
						tables.remove(i);
						break;
					}
				}
			}
			
			if(tables.size() > 0) {
				plugin.getWindow().writeLog(this, "Failed to find some SMObjects. Reading default");
			}
		} else {
			plugin.getWindow().writeLog(this, "Creating SMObjects");
			
			int size = tables.size();
			plugin.getWindow().writeLog(this, "Creating " + size + " SMObject" + (size == 1 ? "":"s"));
		}
		
		plugin.getWindow().setProgressBar(0);
		int pointerIndex = 0;
		
		for(FunctionPointer func : tables) {
			SMDefinition object = findSMObject(func);
			list.add(object);
			
			StringBuilder sb = new StringBuilder();
			sb.append(object.getConstant()).append(", ");
			sb.append(object.getName()).append(", ");
			sb.append(object.getTabledata()).append(", ");
			sb.append(object.getUserdata()).append(", ");
			sb.append(object.getHidden()).append(", ");
			sb.append(object.getType());
			
			manager.addBookmark(func.entry, BookmarkCategory.TABLE_ELEMENT, sb.toString());
			int size = tables.size();
			
			plugin.getWindow().setProgressBar((++pointerIndex) / (size + 0.0), size);
		}
		
		plugin.getWindow().setProgressBar(1);
		plugin.getWindow().writeLog(this, "Took " + (System.currentTimeMillis() - time) + " ms");
		
		return list;
	}
}
