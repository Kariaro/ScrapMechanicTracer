package sm.hardcoded.plugin.tracer;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;

import javax.swing.ImageIcon;

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
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import resources.ResourceManager;

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
	private ScrapMechanicBookmarkManager bookmarkManager;
	private ScrapMechanicAnalyser analyser;
	private ProgramMemory programMemory;
	
	private boolean scanning;
	
	final ImageIcon icon_64 = ResourceManager.loadImage("sm/hardcoded/plugin/icons/icon_64.png");
	final ImageIcon icon_16 = ResourceManager.loadImage("sm/hardcoded/plugin/icons/icon_16.png");
	
	public ScrapMechanicPlugin(PluginTool tool) {
		super(tool, false, false);
	}
	
	protected void programOpened(Program program) {
		updateScanOptions();
	}
	
	protected void programClosed(Program program) {
		updateScanOptions();
	}
	
	protected void programActivated(Program program) {
		updateScanOptions();
	}
	
	protected boolean canClose() {
		return !scanning;
	}
	
	private void updateScanOptions() {
		if(provider != null) {
			provider.setScanEnabled(getCurrentProgram() != null);
			
			if(bookmarkManager != null) {
				provider.setResetScanEnabled(bookmarkManager.hasBookmarks());
			}
		}
	}
	
	public void init() {
		super.init();
		
		provider = new ScrapMechanicWindowProvider(this);
		bookmarkManager = new ScrapMechanicBookmarkManager(this);
		programMemory = new ProgramMemory(this);
		analyser = new ScrapMechanicAnalyser(this);
		
		setupActions();
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
		action.setToolBarData(new ToolBarData(icon_64));
		tool.addAction(action);
	}
	
	/**
	 * Start scanning the current program.
	 */
	public void startScan() {
		Thread thread = new Thread(() -> {
			int transactionId = -1;
			try {
				scanning = true;
				
				transactionId = currentProgram.startTransaction("ScrapMechanicPlugin - Scan");
				
				boolean result = analyser.startAnalysis();
				if(!result) {
					Msg.showError(this, provider.getComponent(), "Start analysis failed", analyser.getLastError());
				}
				
				currentProgram.endTransaction(transactionId, result);
			} catch(Throwable e) {
				ByteArrayOutputStream bs = new ByteArrayOutputStream();
				PrintWriter writer = new PrintWriter(bs);
				e.printStackTrace(writer);
				writer.flush();
				writer.close();
				
				Msg.showError(this, provider.getComponent(), "Exception: " + e.getCause(), new String(bs.toByteArray()));
				
				if(transactionId != -1) {
					currentProgram.endTransaction(transactionId, false);
				}
			} finally {
				updateScanOptions();
				scanning = false;
			}
		});
		
		thread.start();
	}
	
	public ScrapMechanicBookmarkManager getBookmarkManager() {
		return bookmarkManager;
	}
	
	public ScrapMechanicWindowProvider getWindow() {
		return provider;
	}
	
	public ProgramMemory getProgramMemory() {
		return programMemory;
	}
	
	protected void dispose() {
		super.dispose();
		provider.setVisible(false);
	}
}
