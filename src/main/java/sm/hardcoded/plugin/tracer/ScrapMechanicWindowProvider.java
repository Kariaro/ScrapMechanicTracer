package sm.hardcoded.plugin.tracer;

import java.awt.*;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.Msg;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import sm.hardcoded.plugin.exporter.JsonExporter;
import sm.hardcoded.plugin.exporter.SmmJsonExporter;
import sm.hardcoded.plugin.html.SMHtml;
import sm.hardcoded.plugin.json.JsonMap;
import sm.hardcoded.plugin.json.JsonObject;
import sm.hardcoded.plugin.json.JsonParser;

/**
 * This class is the window provider for the ScrapMechanicTracer GhidraPlugin.
 * 
 * @author HardCoded
 * @date 2020-11-27
 */
public class ScrapMechanicWindowProvider extends ComponentProviderAdapter {
	/**
	 * Returns the default plugin home directory
	 */
	public static final String getDefaultSavePath() {
		File tracePath = new File(SMPrefs.getSavePath(), "traces");
		if(!tracePath.exists()) tracePath.mkdir();
		return tracePath.getAbsolutePath();
	}
	
	private final ScrapMechanicPlugin plugin;
	private final SMPrefs prefs;
	private GhidraFileChooser fileChooser;
	private final GhidraFileFilter TRACE_FILTER = new GhidraFileFilter() {
		public String getDescription() {
			return "Trace Files (*.trace)";
		}
		
		public boolean accept(File pathname, GhidraFileChooserModel model) {
			if(pathname.isDirectory()) return true;
			return pathname.getName().endsWith(".trace");
		}
	};
	
	private JComponent mainPanel;
	private Thread messageThread;
	private File loadedTrace;
	
	ScrapMechanicWindowProvider(ScrapMechanicPlugin tool) {
		super(tool.getTool(), "ScrapMechanicTracer", tool.getName());
		plugin = tool;
		prefs = tool.getPreferences();
		
		createComponent();
		
		messageThread = new Thread(messageRunner);
		messageThread.setDaemon(true);
		messageThread.setPriority(Thread.MIN_PRIORITY);
		messageThread.setName("ScrapMechanicWindowProvider.messageQueue");
		messageThread.start();
	}
	
	protected void finalize() throws Throwable {
		messageThread.interrupt();
		messageThread.join();
	}
	
	public JComponent getComponent() {
		return mainPanel;
	}
	
	private JLabel label_status;
	private JLabel label_version;
	private JLabel label_functions;
	private JTextField textField_savePath;
	private JTextArea textArea_logging;
	private JProgressBar progressBar;
	private JButton btnScan;
	private JButton btnOpenTrace;
	private JButton btnResetScan;
	private JButton btnBrowserPath;
	private JComboBox<Integer> comboBox_threads;
	private JComboBox<Integer> comboBox_searchDepth;
	
	public void setStatusText(String string) {
		label_status.setText(string);
	}
	
	public void setVersionText(String string) {
		label_version.setText(Objects.toString(string, ""));
	}
	
	public void setFunctionsText(String string) { 
		label_functions.setText(string);
	}
	
	public void setScanEnabled(boolean b) {
		btnScan.setEnabled(b);
		btnResetScan.setEnabled(b);
		btnBrowserPath.setEnabled(b);
		comboBox_threads.setEnabled(b);
		comboBox_searchDepth.setEnabled(b);
		// btnOpenTrace.setEnabled(b);
	}
	
	public void setResetScanEnabled(boolean b) {
		// The reset scan button is not good enough right now..
		// TODO: Update the bookmark manager gui when you press the reset scan button.
		
		btnResetScan.setEnabled(b);
	}
	
	public void setProgressBar(double percentage) {
		setProgressBar(percentage, 100);
	}
	
	public void setProgressBar(double percentage, int max) {
		int value = (int)(percentage * 10000);
		if(value < 0) value = 0;
		if(value > 10000) value = 10000;
		
		progressBar.setValue(value);
		progressBar.setString((value / 100) + " %");
	}
	
	private ConcurrentLinkedQueue<String> message_queue = new ConcurrentLinkedQueue<>();
	private Runnable messageRunner = new Runnable() {
		public void run() {
			while(!Thread.interrupted()) {
				try {
					Thread.sleep(50);
					if(message_queue.isEmpty()) continue;
				} catch(InterruptedException e) {
					break;
				}
				
				StringBuilder sb = new StringBuilder(textArea_logging.getText());
				while(!message_queue.isEmpty()) {
					sb.append(message_queue.poll());
				}
				
				// Make sure that we do not have empty first line.
				if(sb.charAt(0) == '\n') {
					sb.deleteCharAt(0);
				}
				
				textArea_logging.setText(sb.toString());
			}
		}
	};
	private JTextField textField_loadedTrace;
	
	public synchronized void writeLog(Object caller, String string) {
		writeLog(caller.getClass().getSimpleName(), string);
	}
	
	public synchronized void writeLog(String caller, String string) {
		String message = "\n" + caller + ": " + string;
		message_queue.add(message);
	}
	
	public void clearLogger() {
		// This could maybe interfere with the queue
		textArea_logging.setText("");
	}
	
	///////////////////////////////////////////////////
	// Properties                                    //
	///////////////////////////////////////////////////
	
	public String getVersionString() {
		return label_version.getText();
	}
	
	private void createComponent() {
		mainPanel = new JPanel();
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
		
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		tabbedPane.setFocusable(false);
		mainPanel.add(tabbedPane);
		
		
		createScanningTab(tabbedPane);
		createExporterTab(tabbedPane);
		
		JPanel panel = new JPanel();
		mainPanel.add(panel);
		
		JLabel lblNewLabel_2 = new JLabel("Made by HardCoded");
		panel.add(lblNewLabel_2);
		
		JButton btnGitHub = new JButton();
		btnGitHub.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		btnGitHub.setBorder(null);
		btnGitHub.setText("GitHub");
		btnGitHub.setToolTipText("https://github.com/Kariaro");
		btnGitHub.setForeground(Color.BLUE);
		btnGitHub.setFocusable(false);
		panel.add(btnGitHub);
		btnGitHub.addActionListener((event) -> {
			try {
				Desktop.getDesktop().browse(new URI("https://github.com/Kariaro"));
			} catch(IOException | URISyntaxException e) {
				Logger.log(e);
			}
		});
		
		JButton btnTwitch = new JButton();
		btnTwitch.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		btnTwitch.setBorder(null);
		btnTwitch.setText("Twitch");
		btnTwitch.setToolTipText("https://www.twitch.tv/hard_coded");
		btnTwitch.setForeground(Color.BLUE);
		btnTwitch.setFocusable(false);
		panel.add(btnTwitch);
		btnTwitch.addActionListener((event) -> {
			try {
				Desktop.getDesktop().browse(new URI("https://www.twitch.tv/hard_coded"));
			} catch(IOException | URISyntaxException e) {
				Logger.log(e);
			}
		});
	}
	
	private void createScanningTab(JTabbedPane tabbedPane) {
		JSplitPane splitPane = new JSplitPane();
		splitPane.setContinuousLayout(true);
		tabbedPane.addTab("Scanning", null, splitPane, null);
		
		JPanel panelInformation = new JPanel();
		panelInformation.setMinimumSize(new Dimension(160, 10));
		panelInformation.setPreferredSize(new Dimension(160, 10));
		panelInformation.setMaximumSize(new Dimension(160, 32767));
		panelInformation.setBorder(new TitledBorder(null, "Information", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		splitPane.setLeftComponent(panelInformation);
		
		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{0, 0, 0};
		gbl_panel.rowHeights = new int[]{0, 0, 0, 0, 0};
		gbl_panel.columnWeights = new double[]{1.0, 0.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panelInformation.setLayout(gbl_panel);
		
		JLabel lblStatus = new JLabel("Status");
		GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
		gbc_lblNewLabel.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblNewLabel.insets = new Insets(5, 5, 25, 5);
		gbc_lblNewLabel.gridx = 0;
		gbc_lblNewLabel.gridy = 0;
		panelInformation.add(lblStatus, gbc_lblNewLabel);
		
		label_status = new JLabel("Not Analysed");
		GridBagConstraints gbc_lblNewLabel_1 = new GridBagConstraints();
		gbc_lblNewLabel_1.anchor = GridBagConstraints.NORTHEAST;
		gbc_lblNewLabel_1.insets = new Insets(5, 0, 25, 5);
		gbc_lblNewLabel_1.gridx = 1;
		gbc_lblNewLabel_1.gridy = 0;
		panelInformation.add(label_status, gbc_lblNewLabel_1);
		
		JLabel lblInformation = new JLabel("Information");
		GridBagConstraints gbc_lblInformation = new GridBagConstraints();
		gbc_lblInformation.anchor = GridBagConstraints.WEST;
		gbc_lblInformation.insets = new Insets(0, 5, 5, 5);
		gbc_lblInformation.gridx = 0;
		gbc_lblInformation.gridy = 1;
		panelInformation.add(lblInformation, gbc_lblInformation);
		
		JLabel lblVersion = new JLabel("Version");
		lblVersion.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_lblVersion = new GridBagConstraints();
		gbc_lblVersion.anchor = GridBagConstraints.WEST;
		gbc_lblVersion.insets = new Insets(0, 15, 5, 5);
		gbc_lblVersion.gridx = 0;
		gbc_lblVersion.gridy = 2;
		panelInformation.add(lblVersion, gbc_lblVersion);
		
		label_version = new JLabel("<none>");
		GridBagConstraints gbc_lblNewLabel_13 = new GridBagConstraints();
		gbc_lblNewLabel_13.anchor = GridBagConstraints.EAST;
		gbc_lblNewLabel_13.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel_13.gridx = 1;
		gbc_lblNewLabel_13.gridy = 2;
		panelInformation.add(label_version, gbc_lblNewLabel_13);
		
		JLabel lblFunctions = new JLabel("Functions");
		GridBagConstraints gbc_lblFunctions = new GridBagConstraints();
		gbc_lblFunctions.anchor = GridBagConstraints.WEST;
		gbc_lblFunctions.insets = new Insets(0, 15, 0, 5);
		gbc_lblFunctions.gridx = 0;
		gbc_lblFunctions.gridy = 3;
		panelInformation.add(lblFunctions, gbc_lblFunctions);
		
		label_functions = new JLabel("<none>");
		GridBagConstraints gbc_label_1 = new GridBagConstraints();
		gbc_label_1.insets = new Insets(0, 0, 0, 5);
		gbc_label_1.anchor = GridBagConstraints.EAST;
		gbc_label_1.gridx = 1;
		gbc_label_1.gridy = 3;
		panelInformation.add(label_functions, gbc_label_1);
		
		JPanel panel_1 = new JPanel();
		splitPane.setRightComponent(panel_1);
		panel_1.setLayout(new BoxLayout(panel_1, BoxLayout.Y_AXIS));
		
		JPanel panelSettings = new JPanel();
		panelSettings.setBorder(new TitledBorder(null, "Settings", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		panel_1.add(panelSettings);
		GridBagLayout gbl_panel_2 = new GridBagLayout();
		gbl_panel_2.columnWidths = new int[]{0, 0, 0};
		gbl_panel_2.rowHeights = new int[]{0, 0, 0, 0, 0, 0};
		gbl_panel_2.columnWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		gbl_panel_2.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panelSettings.setLayout(gbl_panel_2);
		
		JLabel lblSavePath = new JLabel("Trace Save Path");
		GridBagConstraints gbc_lblNewLabel_12 = new GridBagConstraints();
		gbc_lblNewLabel_12.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel_12.insets = new Insets(0, 5, 5, 30);
		gbc_lblNewLabel_12.gridx = 0;
		gbc_lblNewLabel_12.gridy = 0;
		panelSettings.add(lblSavePath, gbc_lblNewLabel_12);
		
		JPanel panel_4 = new JPanel();
		GridBagConstraints gbc_panel_4 = new GridBagConstraints();
		gbc_panel_4.insets = new Insets(0, 0, 5, 0);
		gbc_panel_4.fill = GridBagConstraints.BOTH;
		gbc_panel_4.gridx = 1;
		gbc_panel_4.gridy = 0;
		panelSettings.add(panel_4, gbc_panel_4);
		panel_4.setLayout(new BoxLayout(panel_4, BoxLayout.X_AXIS));
		
		textField_savePath = new JTextField();
		textField_savePath.setEditable(false);
		textField_savePath.setText(prefs.getTracePath());
		textField_savePath.setMinimumSize(new Dimension(6, 21));
		textField_savePath.setMaximumSize(new Dimension(2147483647, 21));
		textField_savePath.setMargin(new Insets(0, 3, 0, 0));
		textField_savePath.setDisabledTextColor(Color.WHITE);
		textField_savePath.setColumns(10);
		panel_4.add(textField_savePath);
		
		fileChooser = new GhidraFileChooser(mainPanel);
		fileChooser.setMultiSelectionEnabled(false);
		
		btnBrowserPath = new JButton("Browser");
		btnBrowserPath.setHorizontalAlignment(SwingConstants.LEADING);
		btnBrowserPath.setFocusable(false);
		btnBrowserPath.setAlignmentX(1.0f);
		btnBrowserPath.addActionListener((event) -> {
			if(fileChooser.isShowing()) return;
			fileChooser.setCurrentDirectory(new File(prefs.getTracePath()));
			fileChooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
			
			File file = fileChooser.getSelectedFile();
			if(file != null) {
				prefs.setTracePath(file.getAbsolutePath());
				textField_savePath.setText(file.getAbsolutePath());
				fileChooser.close();
			}
		});
		panel_4.add(btnBrowserPath);
		
		Component horizontalStrut_3 = Box.createHorizontalStrut(-1);
		panel_4.add(horizontalStrut_3);
		
		JButton btnOpenSavePath = new JButton("Open Save Path");
		btnOpenSavePath.setFocusable(false);
		GridBagConstraints gbc_btnOpenSavePath = new GridBagConstraints();
		gbc_btnOpenSavePath.insets = new Insets(0, -1, 5, -1);
		gbc_btnOpenSavePath.fill = GridBagConstraints.BOTH;
		gbc_btnOpenSavePath.gridx = 1;
		gbc_btnOpenSavePath.gridy = 1;
		panelSettings.add(btnOpenSavePath, gbc_btnOpenSavePath);
		btnOpenSavePath.addActionListener((event) -> {
			try {
				File folder = new File(prefs.getTracePath());
				if(!folder.exists()) folder.mkdirs();
				Desktop.getDesktop().open(folder);
			} catch(IOException e) {
				Logger.log(e);
			}
		});
		
		JLabel lblThreads = new JLabel("Threads");
		GridBagConstraints gbc_lblDecompileThreads = new GridBagConstraints();
		gbc_lblDecompileThreads.anchor = GridBagConstraints.WEST;
		gbc_lblDecompileThreads.insets = new Insets(0, 5, 5, 5);
		gbc_lblDecompileThreads.gridx = 0;
		gbc_lblDecompileThreads.gridy = 2;
		panelSettings.add(lblThreads, gbc_lblDecompileThreads);
		
		comboBox_threads = new JComboBox<Integer>();
		comboBox_threads.setFocusable(false);
		{
			Integer[] array = new Integer[Runtime.getRuntime().availableProcessors() - 1];
			for(int i = 0; i < array.length; i++) array[i] = Integer.valueOf(i + 1);
			comboBox_threads.setModel(new DefaultComboBoxModel<>(array));
			comboBox_threads.setSelectedIndex(prefs.getNumThreads() - 1);
			comboBox_threads.addActionListener(e -> prefs.setNumThreads(comboBox_threads.getSelectedIndex() + 1));
		}
		
		GridBagConstraints gbc_comboBox = new GridBagConstraints();
		gbc_comboBox.insets = new Insets(0, 0, 5, 0);
		gbc_comboBox.fill = GridBagConstraints.HORIZONTAL;
		gbc_comboBox.gridx = 1;
		gbc_comboBox.gridy = 2;
		panelSettings.add(comboBox_threads, gbc_comboBox);
		
		JLabel lblSearchDepth = new JLabel("Max Search Depth");
		GridBagConstraints gbc_lblNewLabel_2 = new GridBagConstraints();
		gbc_lblNewLabel_2.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel_2.insets = new Insets(0, 5, 5, 5);
		gbc_lblNewLabel_2.gridx = 0;
		gbc_lblNewLabel_2.gridy = 3;
		panelSettings.add(lblSearchDepth, gbc_lblNewLabel_2);
		
		comboBox_searchDepth = new JComboBox<Integer>();
		comboBox_searchDepth.setFocusable(false);
		comboBox_searchDepth.setModel(new DefaultComboBoxModel<>(new Integer[] { 1, 2, 3, 4, 5 }));
		comboBox_searchDepth.setSelectedIndex(prefs.getSearchDepth() - 1);
		comboBox_searchDepth.addActionListener(e -> prefs.setSearchDepth(comboBox_searchDepth.getSelectedIndex() + 1));
		GridBagConstraints gbc_comboBox_1 = new GridBagConstraints();
		gbc_comboBox_1.insets = new Insets(0, 0, 5, 0);
		gbc_comboBox_1.fill = GridBagConstraints.HORIZONTAL;
		gbc_comboBox_1.gridx = 1;
		gbc_comboBox_1.gridy = 3;
		panelSettings.add(comboBox_searchDepth, gbc_comboBox_1);
		
		btnResetScan = new JButton("Reset Scan Data");
		GridBagConstraints gbc_btnNewButton_1 = new GridBagConstraints();
		gbc_btnNewButton_1.insets = new Insets(0, -1, 0, -1);
		gbc_btnNewButton_1.fill = GridBagConstraints.BOTH;
		gbc_btnNewButton_1.gridx = 1;
		gbc_btnNewButton_1.gridy = 4;
		panelSettings.add(btnResetScan, gbc_btnNewButton_1);
		btnResetScan.setEnabled(false);
		btnResetScan.setFocusable(false);
		btnResetScan.addActionListener((e) -> {
			plugin.getBookmarkManager().clearBookmarks();
			btnResetScan.setEnabled(false);
		});
		
		JPanel panelLogger = new JPanel();
		panelLogger.setPreferredSize(new Dimension(10, 32767));
		panelLogger.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Log", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_1.add(panelLogger);
		GridBagLayout gbl_panelData = new GridBagLayout();
		gbl_panelData.columnWidths = new int[]{0, 0, 0};
		gbl_panelData.rowHeights = new int[]{0, 0, 0};
		gbl_panelData.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
		gbl_panelData.rowWeights = new double[]{1.0, 0.0, Double.MIN_VALUE};
		panelLogger.setLayout(gbl_panelData);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		GridBagConstraints gbc_scrollPane = new GridBagConstraints();
		gbc_scrollPane.insets = new Insets(0, 1, 5, 0);
		gbc_scrollPane.gridwidth = 2;
		gbc_scrollPane.fill = GridBagConstraints.BOTH;
		gbc_scrollPane.gridx = 0;
		gbc_scrollPane.gridy = 0;
		panelLogger.add(scrollPane, gbc_scrollPane);
		
		textArea_logging = new JTextArea();
		textArea_logging.setFont(new Font("Monospaced", Font.PLAIN, 11));
		textArea_logging.setEditable(false);
		textArea_logging.setDisabledTextColor(Color.BLACK);
		scrollPane.setViewportView(textArea_logging);
		
		btnScan = new JButton("Scan");
		btnScan.setFocusable(false);
		btnScan.setEnabled(false);
		GridBagConstraints gbc_btnNewButton_133 = new GridBagConstraints();
		gbc_btnNewButton_133.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnNewButton_133.anchor = GridBagConstraints.WEST;
		gbc_btnNewButton_133.insets = new Insets(0, 0, 0, 5);
		gbc_btnNewButton_133.gridx = 0;
		gbc_btnNewButton_133.gridy = 1;
		panelLogger.add(btnScan, gbc_btnNewButton_133);
		btnScan.addActionListener(e -> plugin.startScan());
		
		progressBar = new JProgressBar();
		progressBar.setPreferredSize(new Dimension(146, 22));
		progressBar.setMaximumSize(new Dimension(32767, 22));
		progressBar.setMinimumSize(new Dimension(10, 22));
		progressBar.setMaximum(10000);
		progressBar.setStringPainted(true);
		GridBagConstraints gbc_progressBar = new GridBagConstraints();
		gbc_progressBar.anchor = GridBagConstraints.SOUTH;
		gbc_progressBar.fill = GridBagConstraints.HORIZONTAL;
		gbc_progressBar.gridx = 1;
		gbc_progressBar.gridy = 1;
		panelLogger.add(progressBar, gbc_progressBar);
	}
	
	private JButton btnExportDocs;
	private JButton btnExportJson;
	private JButton btnExportSimple;
	private JButton btnExportAPIJson;
	
	private JLabel lblAuthorString;
	private JLabel lblVersionString;
	private JLabel lblCommentString;
	private JLabel lblDateString;
	
	private void createExporterTab(JTabbedPane tabbedPane) {
		JPanel splitPane = new JPanel();
		tabbedPane.addTab("Export", null, splitPane, null);
		splitPane.setLayout(new BorderLayout(0, 0));
		
		JPanel panel = new JPanel();
		panel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		splitPane.add(panel, BorderLayout.WEST);
		// splitPane.setLeftComponent(panel);
		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{0, 0};
		gbl_panel.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panel.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel.setLayout(gbl_panel);
		
		JLabel lblNewLabel = new JLabel("Controls");
		lblNewLabel.setMaximumSize(new Dimension(2147483647, 21));
		GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
		gbc_lblNewLabel.insets = new Insets(0, 0, 5, 0);
		gbc_lblNewLabel.ipady = 10;
		gbc_lblNewLabel.gridx = 0;
		gbc_lblNewLabel.gridy = 0;
		panel.add(lblNewLabel, gbc_lblNewLabel);
		
		btnOpenTrace = new JButton("Open Trace");
		btnOpenTrace.setFocusable(false);
		GridBagConstraints gbc_btnOpenTrace = new GridBagConstraints();
		gbc_btnOpenTrace.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnOpenTrace.insets = new Insets(0, 5, 5, 5);
		gbc_btnOpenTrace.gridx = 0;
		gbc_btnOpenTrace.gridy = 1;
		panel.add(btnOpenTrace, gbc_btnOpenTrace);
		
		Component verticalStrut = Box.createVerticalStrut(20);
		GridBagConstraints gbc_verticalStrut = new GridBagConstraints();
		gbc_verticalStrut.insets = new Insets(0, 5, 5, 5);
		gbc_verticalStrut.gridx = 0;
		gbc_verticalStrut.gridy = 2;
		panel.add(verticalStrut, gbc_verticalStrut);
		
		btnExportDocs = new JButton("Export Docs**");
		btnExportDocs.setToolTipText("[EXPERIMENTAL] Export a html page made from the trace");
		btnExportDocs.setFocusable(false);
		btnExportDocs.setEnabled(false);
		GridBagConstraints gbc_btnExportDocs = new GridBagConstraints();
		gbc_btnExportDocs.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnExportDocs.insets = new Insets(0, 5, 5, 5);
		gbc_btnExportDocs.gridx = 0;
		gbc_btnExportDocs.gridy = 3;
		panel.add(btnExportDocs, gbc_btnExportDocs);
		btnExportDocs.addActionListener((event) -> {
			if(loadedTrace == null) return;
			JsonMap json = null;
			
			try {
				json = JsonParser.parseFromFile(loadedTrace).toMap();
			} catch(Exception e) {
				Logger.log(e);
				Msg.showError(this, this.getComponent(), "Export failed", "The trace failed to export.");
				return;
			}
			
			try {
				String version = "none";
				if(json.isString("version")) {
					version = json.getString("version");
				}
				
				SMClass table = JsonExporter.deserialize(json);
				SMHtml.generate(prefs, version, table);
				
				Msg.showInfo(this, this.getComponent(), "Export successful", "The trace has been exported.\nPress [Open Save Path] to view the results.");
			} catch(Exception e) {
				Logger.log(e);
				Msg.showError(this, this.getComponent(), "Export failed", "The trace failed to export.");
			}
		});
		
		btnExportJson = new JButton("Export Json");
		btnExportJson.setEnabled(false);
		btnExportJson.setToolTipText("Export the full json content of the trace");
		btnExportJson.setFocusable(false);
		GridBagConstraints gbc_btnExportJson = new GridBagConstraints();
		gbc_btnExportJson.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnExportJson.insets = new Insets(0, 5, 5, 5);
		gbc_btnExportJson.gridx = 0;
		gbc_btnExportJson.gridy = 4;
		panel.add(btnExportJson, gbc_btnExportJson);
		
		btnExportAPIJson = new JButton("Export API Json");
		btnExportAPIJson.setEnabled(false);
		btnExportAPIJson.setFocusable(false);
		btnExportAPIJson.setToolTipText("Export a simplified json file for other usage");
		GridBagConstraints gbc_btnSimpleJson = new GridBagConstraints();
		gbc_btnSimpleJson.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnSimpleJson.insets = new Insets(0, 5, 5, 5);
		gbc_btnSimpleJson.gridx = 0;
		gbc_btnSimpleJson.gridy = 5;
		panel.add(btnExportAPIJson, gbc_btnSimpleJson);
		btnExportAPIJson.addActionListener((event) -> {
			if(loadedTrace == null) return;
			JsonMap json = null;
			
			try {
				json = JsonParser.parseFromFile(loadedTrace).toMap();
			} catch(Exception e) {
				Logger.log(e);
				Msg.showError(this, this.getComponent(), "Export failed", "The trace failed to export.");
				return;
			}
			
			try {
				String version = "none";
				if(json.isString("version")) {
					version = json.getString("version");
				}
				
				JsonObject smm_json = SmmJsonExporter.convert(
					json,
					"HardCoded",
					version,
					"This json file was made by the ghidra module ScrapMechanicTracer. https://github.com/Kariaro/ScrapMechanicTracer",
					System.currentTimeMillis(),
					Map.of(
						"github", "https://www.twitch.tv/hard_coded",
						"twitter", "https://twitter.com/HardCodedTwitch",
						"twitch", "https://github.com/Kariaro"
					)
				);
				
				File file = new File(prefs.getTracePath());
				file.mkdirs();
				
				String traceString = smm_json.toString();
				File outputFile = new File(file, "simpleJson." + version + "." + System.currentTimeMillis() + ".json");
				try(DataOutputStream stream = new DataOutputStream(new FileOutputStream(outputFile))) {
					stream.write(traceString.getBytes());
				} catch(IOException e) {
					throw e;
				}
				
				Msg.showInfo(this, this.getComponent(), "Export successful", "The trace has been exported.\nPress [Open Save Path] to view the results.");
			} catch(Exception e) {
				Logger.log(e);
				Msg.showError(this, this.getComponent(), "Export failed", "The trace failed to export.");
			}
		});
		
		btnExportSimple = new JButton("Export Simple");
		btnExportSimple.setEnabled(false);
		btnExportSimple.setToolTipText("Export a simple readable version of the trace");
		btnExportSimple.setFocusable(false);
		GridBagConstraints gbc_btnExportSimple = new GridBagConstraints();
		gbc_btnExportSimple.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnExportSimple.insets = new Insets(0, 5, 5, 5);
		gbc_btnExportSimple.gridx = 0;
		gbc_btnExportSimple.gridy = 6;
		panel.add(btnExportSimple, gbc_btnExportSimple);
		btnExportSimple.addActionListener((event) -> {
			if(loadedTrace == null) return;
			JsonMap json = null;
			
			try {
				json = JsonParser.parseFromFile(loadedTrace).toMap();
			} catch(Exception e) {
				Logger.log(e);
				Msg.showError(this, this.getComponent(), "Export failed", "The trace failed to export.");
				return;
			}
			
			try {
				String version = "none";
				if(json.isString("version")) {
					version = json.getString("version");
				}
				
				SMClass table = JsonExporter.deserialize(json);
				File file = new File(prefs.getTracePath());
				file.mkdirs();
				
				String traceString = table.toString();
				File outputFile = new File(file, "lua." + version + ".time." + System.currentTimeMillis() + ".txt");
				try(DataOutputStream stream = new DataOutputStream(new FileOutputStream(outputFile))) {
					stream.write(traceString.getBytes());
				} catch(IOException e) {
					throw e;
				}
				
				Msg.showInfo(this, this.getComponent(), "Export successful", "The trace has been exported.\nPress [Open Save Path] to view the results.");
			} catch(Exception e) {
				Logger.log(e);
				Msg.showError(this, this.getComponent(), "Export failed", "The trace failed to export.");
			}
		});
		
		JButton button = new JButton("Open Save Path");
		button.setFocusable(false);
		GridBagConstraints gbc_button = new GridBagConstraints();
		gbc_button.insets = new Insets(0, 5, 5, 5);
		gbc_button.fill = GridBagConstraints.HORIZONTAL;
		gbc_button.gridx = 0;
		gbc_button.gridy = 7;
		panel.add(button, gbc_button);
		button.addActionListener((event) -> {
			try {
				File folder = new File(prefs.getTracePath());
				if(!folder.exists()) folder.mkdirs();
				Desktop.getDesktop().open(folder);
			} catch(IOException e) {
				Logger.log(e);
			}
		});
		
		btnOpenTrace.addActionListener((event) -> {
			if(fileChooser.isShowing()) return;
			fileChooser.setCurrentDirectory(new File(prefs.getTracePath()));
			fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			fileChooser.setFileFilter(TRACE_FILTER);
			
			File file = fileChooser.getSelectedFile();
			if(file != null) {
				// Open this trace file.
				loadedTrace = file;
				textField_loadedTrace.setText(loadedTrace.getAbsolutePath());
				fileChooser.close();
				
				btnExportSimple.setEnabled(true);
				btnExportDocs.setEnabled(true);
				// btnExportJson.setEnabled(true);
				btnExportAPIJson.setEnabled(true);
				
				try {
					JsonMap json = JsonParser.parseFromFile(loadedTrace).toMap();
					String author = "<none>";
					String version = "<none>";
					String comment = "<none>";
					String time = "<none>";
					
					if(json.isString("author")) author = json.getString("author");
					if(json.isString("version")) version = json.getString("version");
					if(json.isString("comment")) comment = json.getString("comment");
					if(json.isLong("time")) {
						long readTime = json.getLong("time");
						
						DateFormat format = new SimpleDateFormat("YYYY-MM-dd hh:mm:ss");
						Date date = new Date(readTime);
						time = format.format(date);
					}
					
					lblAuthorString.setText(author);
					lblVersionString.setText(version);
					lblCommentString.setText(comment);
					lblDateString.setText(time);
				} catch(Exception e) {
					loadedTrace = null;
					textField_loadedTrace.setText("<Invalid json file>");
					lblAuthorString.setText("<none>");
					lblVersionString.setText("<none>");
					lblCommentString.setText("<none>");
					lblDateString.setText("<none>");
					btnExportSimple.setEnabled(false);
					btnExportDocs.setEnabled(false);
					btnExportJson.setEnabled(false);
					btnExportAPIJson.setEnabled(false);
				}
			}
		});
		
		JPanel panel_1 = new JPanel();
		panel_1.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		splitPane.add(panel_1, BorderLayout.CENTER);
		GridBagLayout gbl_panel_1 = new GridBagLayout();
		gbl_panel_1.columnWidths = new int[]{58, 86, 0};
		gbl_panel_1.rowHeights = new int[]{20, 0, 0, 0, 0, 0};
		gbl_panel_1.columnWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		gbl_panel_1.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_1.setLayout(gbl_panel_1);
		
		JLabel lblNewLabel_1 = new JLabel("Loaded File:");
		lblNewLabel_1.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_lblNewLabel_1 = new GridBagConstraints();
		gbc_lblNewLabel_1.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel_1.ipadx = 5;
		gbc_lblNewLabel_1.insets = new Insets(5, 5, 5, 5);
		gbc_lblNewLabel_1.gridx = 0;
		gbc_lblNewLabel_1.gridy = 0;
		panel_1.add(lblNewLabel_1, gbc_lblNewLabel_1);
		
		textField_loadedTrace = new JTextField();
		textField_loadedTrace.setText("<none>");
		textField_loadedTrace.setDisabledTextColor(Color.BLACK);
		textField_loadedTrace.setEditable(false);
		textField_loadedTrace.setFocusable(false);
		GridBagConstraints gbc_textField = new GridBagConstraints();
		gbc_textField.fill = GridBagConstraints.HORIZONTAL;
		gbc_textField.insets = new Insets(5, 0, 5, 0);
		gbc_textField.anchor = GridBagConstraints.NORTH;
		gbc_textField.gridx = 1;
		gbc_textField.gridy = 0;
		panel_1.add(textField_loadedTrace, gbc_textField);
		textField_loadedTrace.setColumns(10);
		
		JLabel lblAuthor = new JLabel("Author:");
		lblAuthor.setHorizontalAlignment(SwingConstants.LEFT);
		lblAuthor.setPreferredSize(new Dimension(80, 20));
		GridBagConstraints gbc_lblAuthor = new GridBagConstraints();
		gbc_lblAuthor.anchor = GridBagConstraints.WEST;
		gbc_lblAuthor.insets = new Insets(0, 5, 5, 5);
		gbc_lblAuthor.gridx = 0;
		gbc_lblAuthor.gridy = 1;
		panel_1.add(lblAuthor, gbc_lblAuthor);
		
		lblAuthorString = new JLabel("<none>");
		lblAuthorString.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_lblAuthorString = new GridBagConstraints();
		gbc_lblAuthorString.anchor = GridBagConstraints.WEST;
		gbc_lblAuthorString.insets = new Insets(0, 0, 5, 0);
		gbc_lblAuthorString.gridx = 1;
		gbc_lblAuthorString.gridy = 1;
		panel_1.add(lblAuthorString, gbc_lblAuthorString);
		
		JLabel lblVersion = new JLabel("Version:");
		lblVersion.setPreferredSize(new Dimension(80, 20));
		lblVersion.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_lblVersion = new GridBagConstraints();
		gbc_lblVersion.anchor = GridBagConstraints.WEST;
		gbc_lblVersion.insets = new Insets(0, 5, 5, 5);
		gbc_lblVersion.gridx = 0;
		gbc_lblVersion.gridy = 2;
		panel_1.add(lblVersion, gbc_lblVersion);
		
		lblVersionString = new JLabel("<none>");
		GridBagConstraints gbc_lblVersionString = new GridBagConstraints();
		gbc_lblVersionString.insets = new Insets(0, 0, 5, 0);
		gbc_lblVersionString.anchor = GridBagConstraints.WEST;
		gbc_lblVersionString.gridx = 1;
		gbc_lblVersionString.gridy = 2;
		panel_1.add(lblVersionString, gbc_lblVersionString);
		
		JLabel lblComment = new JLabel("Comment:");
		lblComment.setHorizontalAlignment(SwingConstants.LEFT);
		lblComment.setPreferredSize(new Dimension(80, 20));
		GridBagConstraints gbc_lblComment = new GridBagConstraints();
		gbc_lblComment.anchor = GridBagConstraints.WEST;
		gbc_lblComment.insets = new Insets(0, 5, 5, 5);
		gbc_lblComment.gridx = 0;
		gbc_lblComment.gridy = 3;
		panel_1.add(lblComment, gbc_lblComment);
		
		lblCommentString = new JLabel("<none>");
		lblCommentString.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_lblCommentString = new GridBagConstraints();
		gbc_lblCommentString.anchor = GridBagConstraints.WEST;
		gbc_lblCommentString.insets = new Insets(0, 0, 5, 0);
		gbc_lblCommentString.gridx = 1;
		gbc_lblCommentString.gridy = 3;
		panel_1.add(lblCommentString, gbc_lblCommentString);
		
		JLabel lblDate = new JLabel("Date:");
		lblDate.setPreferredSize(new Dimension(80, 20));
		lblDate.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_lblTime = new GridBagConstraints();
		gbc_lblTime.anchor = GridBagConstraints.WEST;
		gbc_lblTime.insets = new Insets(0, 5, 5, 5);
		gbc_lblTime.gridx = 0;
		gbc_lblTime.gridy = 4;
		panel_1.add(lblDate, gbc_lblTime);
		
		lblDateString = new JLabel("<none>");
		lblDateString.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc_lblTimeString = new GridBagConstraints();
		gbc_lblTimeString.anchor = GridBagConstraints.WEST;
		gbc_lblTimeString.insets = new Insets(0, 0, 5, 0);
		gbc_lblTimeString.gridx = 1;
		gbc_lblTimeString.gridy = 4;
		panel_1.add(lblDateString, gbc_lblTimeString);
	}
}
