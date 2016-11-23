package cranium;

import burp.IBurpExtenderCallbacks;
import burp.ITab;

import javax.swing.*;
import java.awt.*;

public class Cranium implements ITab {

	private MessageEditor messageEditor;
	private JSplitPane splitPane;
	private UniqueHeadersTable headersTable;
	private UniqueHeaderValuesTable headerValuesTable;

	public Cranium(IBurpExtenderCallbacks callbacks) {
		SwingUtilities.invokeLater(() -> {
			// Custom Components
			messageEditor = new MessageEditor(callbacks);
			headerValuesTable = new UniqueHeaderValuesTable(messageEditor);
			headersTable = new UniqueHeadersTable(headerValuesTable, callbacks);

			// Layout
			JSplitPane upperPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
			JScrollPane scrollPane = new JScrollPane(headersTable);
			JScrollPane headerScrollPane = new JScrollPane(headerValuesTable);
			upperPane.setLeftComponent(scrollPane);
			upperPane.setRightComponent(headerScrollPane);

			splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
			splitPane.setTopComponent(upperPane);
			splitPane.setBottomComponent(messageEditor);

			callbacks.customizeUiComponent(splitPane);

			callbacks.addSuiteTab(Cranium.this);
			callbacks.registerHttpListener(headersTable);
		});
	}

	@Override
	public Component getUiComponent() {
		return splitPane;
	}

	@Override
	public String getTabCaption() {
		return "Cranium";
	}


}
