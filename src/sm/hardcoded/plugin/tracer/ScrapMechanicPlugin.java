package sm.hardcoded.plugin.tracer;

import java.io.File;
import java.util.List;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.main.FrontEndable;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import resources.ResourceManager;
import sm.SMObject;

@PluginInfo(
	category = PluginCategoryNames.ANALYSIS,
	packageName = "sm.hardcoded.plugin.tracer.ScrapMechanicPlugin",
	shortDescription = "This plugin finds the argument values for each lua function.",
	description = "This plugin finds the argument values for each lua function.",
	status = PluginStatus.STABLE,
	isSlowInstallation = false
)
public class ScrapMechanicPlugin extends ProgramPlugin implements FrontEndable {
	private ScrapMechanicWindowProvider provider;
	
	private TableElementFinder elementFinder;
	private TableFinder tableFinder;
	
	public ScrapMechanicPlugin(PluginTool tool) {
		super(tool, false, false);
	}
	
	@Override
	protected void programOpened(Program program) {
		// Msg.debug(this, "Program Opened: " + program);
		if(provider == null) return;
		provider.setScanEnabled(getCurrentProgram() != null);
	}
	
	@Override
	protected void programClosed(Program program) {
		// Msg.debug(this, "Program Closed: " + program);
		if(provider == null) return;
		provider.setScanEnabled(getCurrentProgram() != null);
	}
	
	@Override
	protected void programActivated(Program program) {
		// Msg.debug(this, "Program Activated: " + program);
		// Change active program
		if(provider == null) return;
		provider.setScanEnabled(getCurrentProgram() != null);
	}
	
	public void init() {
		super.init();
		
		provider = new ScrapMechanicWindowProvider(this);
		elementFinder = new TableElementFinder(this);
		tableFinder = new TableFinder(this);
		
		setupActions();
	}
	
	public String getPluginHome() {
		String userHome = System.getProperty("user.home");
		File pluginHome = new File(userHome, "ScrapMechanicGhidraPlugin");
		if(!pluginHome.exists()) pluginHome.mkdir();
		
		File tracePath = new File(pluginHome, "traces");
		if(!tracePath.exists()) tracePath.mkdir();
		
		return pluginHome.getAbsolutePath();
	}
	
	public void readConfigState(SaveState saveState) {
		if(provider == null) return;
		
		provider.setThreads(saveState.getInt("threads", 1));
		provider.setSearchDepth(saveState.getInt("searchDepth", 1));
		provider.setSavePath(saveState.getString("savePath", null));
	}
	
	public void writeConfigState(SaveState saveState) {
		if(provider == null) return;
		
		saveState.putInt("threads", provider.getThreads());
		saveState.putInt("searchDepth", provider.getSearchDepth());
		saveState.putString("savePath", provider.getSavePath());
		
	}
	
	private void setupActions() {
		DockingAction action = new DockingAction("ScrapMechanicView", getName()) {
			public void actionPerformed(ActionContext context) {
				provider.setVisible(true);
			}
		};
		
		DockingWindowManager.getHelpService().excludeFromHelp(action);
		action.setToolBarData(new ToolBarData(ResourceManager.loadImage("sm/hardcoded/plugin/icons/icon_64.png")));
		tool.addAction(action);
	}
	
	/**
	 * Start scanning the current program.
	 */
	public void startScan() {
		int transactionId = currentProgram.startTransaction("ScrapMechanicPlugin - Scan");
		Msg.debug(this, "Start scan was pressed");
		
		// Disallow the user to change the current program while the tracer is scanning.
		
		// TODO: Use the bookmark manager to cache data locations..
		
		if(false) {
			try {
				tableFinder.loadMemory();
			} catch(MemoryAccessException e) {
				e.printStackTrace();
				Msg.showError(this, provider.getComponent(), "Failed to load memory", e.getMessage());
				return;
			}
			
			List<FunctionPointer> tables = tableFinder.findFunctionTable();
			for(FunctionPointer func : tables) {
				Msg.debug(this, "Register function: (" + func.name + ") [" + func.entry + "]");
				/*
				if(func.name.equals("sm.construction")) {
					Msg.warn(this, "new FunctionPointer(new StringPointer(" + func.stringPointer.addr + ", " + func.name + "), " + func.entry + ", " + func.location + ");");
				}*/
			}
		}
		
		AddressFactory fact = currentProgram.getAddressFactory();
		FunctionPointer func = new FunctionPointer(new StringPointer(fact.getAddress("00e7f0d8"), "sm.construction"), fact.getAddress("0080c1b0"), fact.getAddress("00fe4038"));
		SMObject object = elementFinder.findSMObject(func);

		Msg.debug(this, object.toString());
		
		currentProgram.endTransaction(transactionId, true);
		
		// currentProgram.getBookmarkManager().setBookmark(addr, type, category, comment)
	}
	
	protected void dispose() {
		super.dispose();
		provider.setVisible(false);
	}
}
