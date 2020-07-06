package sm.hardcoded.plugin.tracer;

import java.awt.Color;
import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

/**
 * The bookmark system that ghidra provides can be used to label all the data
 * that we need to keep track of.<br>
 * 
 * This class is a simplified implementation of the build in BookmarkManager that
 * will store important pointers.
 * 
 * @author HardCoded
 */
class ScrapMechanicBookmarkManager {
	private static final String BOOKMARK_TYPE = "ScrapMechanicTracerAnalysis";
	private final ScrapMechanicPlugin plugin;
	
	ScrapMechanicBookmarkManager(ScrapMechanicPlugin tool) {
		plugin = tool;
	}
	
	public List<Bookmark> getBookmarks(BookmarkCategory category) {
		Program program = plugin.getCurrentProgram();
		if(program == null) return Collections.emptyList();
		
		BookmarkManager manager = program.getBookmarkManager();
		if(manager == null) return Collections.emptyList();
		
		BookmarkType type = getBookmarkType(manager);
		
		List<Bookmark> list = new ArrayList<>();
		Iterator<Bookmark> iter = manager.getBookmarksIterator(type.getTypeString());
		while(iter.hasNext()) {
			Bookmark bookmark = iter.next();
			
			if(bookmark.getCategory().equals(category.name)) {
				list.add(bookmark);
			}
		}
		
		return list;
	}
	
	public Bookmark getBookmarkFromAddress(Address address, BookmarkCategory category) {
		return getBookmarkFromAddress(address == null ? null:address.toString(), category);
	}
	
	public Bookmark getBookmarkFromAddress(String address, BookmarkCategory category) {
		List<Bookmark> list = getBookmarks(category);
		
		for(Bookmark bookmark : list) {
			String string = bookmark.getAddress().toString();
			if(string.equals(address)) {
				return bookmark;
			}
		}
		
		return null;
	}
	
	public void addBookmark(Address address, BookmarkCategory category, String description) {
		Program program = plugin.getCurrentProgram();
		if(program == null) return;
		
		BookmarkManager manager = program.getBookmarkManager();
		if(manager == null) return;
		
		BookmarkType type = getBookmarkType(manager);
		manager.setBookmark(address, type.getTypeString(), category.name, description);
	}
	
	private BookmarkType getBookmarkType(BookmarkManager manager) {
		BookmarkType type = manager.getBookmarkType(BOOKMARK_TYPE);
		if(type == null || type.getIcon() == null) {
			type = manager.defineType(BOOKMARK_TYPE, plugin.icon_16, Color.CYAN, 0);
		}
		
		return type;
	}
	
	public boolean hasBookmarks() {
		Program program = plugin.getCurrentProgram();
		if(program == null) return false;
		
		BookmarkManager manager = program.getBookmarkManager();
		if(manager == null) return false;
		
		BookmarkType type = getBookmarkType(manager);
		return manager.hasBookmarks(type.getTypeString());
	}
	

	public boolean clearBookmarks() {
		Program program = plugin.getCurrentProgram();
		if(program == null) return false;
		
		BookmarkManager manager = program.getBookmarkManager();
		if(manager == null) return false;
		
		// TODO: Maybe add a yes no dialog so that we do not accidentally remove all the bookmarks
		
		int transactionId = program.startTransaction("ScrapMechanicPlugin - ResetScanData");
		BookmarkType type = getBookmarkType(manager);
		manager.removeBookmarks(type.getTypeString());
		program.endTransaction(transactionId, true);
		
		return true;
	}
	
	public static enum BookmarkCategory {
		DEFINING_FUNCTION("Defining Function"),
		STRING_POINTER("String Pointer"),
		TABLE_ELEMENT("Table Function"),
		LUA_TYPE("Lua Type");
		
		public final String name;
		private BookmarkCategory(String name) {
			this.name = name;
		}
	}
}
