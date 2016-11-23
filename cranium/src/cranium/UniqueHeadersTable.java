package cranium;

import burp.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Pattern;


public class UniqueHeadersTable extends JTable implements IHttpListener {

	private final UniqueHeadersTableModel model = new UniqueHeadersTableModel();
	private final UniqueHeaderValuesTable headerValuesTable;
	private final IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	// TODO: Configurable ignored headers
	private final Pattern ignoredHeadersPattern = Pattern.compile("(Last-Modified|Cache-Control|Expires|Date|Content-Length)");


	public UniqueHeadersTable(UniqueHeaderValuesTable headerValuesTable, IBurpExtenderCallbacks callbacks) {
		super();
		this.setModel(model);
		this.headerValuesTable = headerValuesTable;
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();
	}

	@Override
	public void changeSelection(int row, int col, boolean toggle, boolean extend) {
		String headerName = model.getUniqueHeaderNames().get(row);
		headerValuesTable.setHeaderValues(new ArrayList<>(model.getHeaderValuesMap().get(headerName)));
		super.changeSelection(row, col, toggle, extend);
	}


	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (!messageIsRequest) {
			synchronized (model.getUniqueHeaderNames()) {
				int startRow = model.getUniqueHeaderNames().size();
				int endRow = startRow;
				IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
				IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
				// TODO: Make in scope exclusion configurable
				if (callbacks.isInScope(requestInfo.getUrl())) {


					for (String header : responseInfo.getHeaders().subList(1, responseInfo.getHeaders().size())) {

						String[] headerInfo = header.split(":", 2);
						String name = headerInfo[0];
						String value = headerInfo[1];

						if (ignoredHeadersPattern.matcher(name).find()) {
							continue;
						}

						if (!model.getHeaderValuesMap().containsKey(name)) {
							model.getHeaderValuesMap().put(name, new LinkedHashSet<>());
						}
						HeaderValue headerValue = new HeaderValue(value, callbacks.saveBuffersToTempFiles(messageInfo));
						model.getHeaderValuesMap().get(name).add(headerValue);
						if (!model.getUniqueHeaderNames().contains(name)) {
							model.getUniqueHeaderNames().add(name);
							endRow++;
						}
					}
					if (endRow > startRow) {
						model.fireTableRowsInserted(startRow, endRow - 1);
					}

				}
			}
		}
	}

	private static class UniqueHeadersTableModel extends AbstractTableModel {

		private final List<String> uniqueHeaderNames = new ArrayList<>();
		private final HashMap<String, LinkedHashSet<HeaderValue>> headerValuesMap = new HashMap<>();

		@Override
		public String getColumnName(int columnIndex) {
			switch (columnIndex) {
				case 0:
					return "Header Name";
				case 1:
					return "Example Value";
				default:
					return "";
			}
		}


		@Override
		public int getRowCount() {
			return uniqueHeaderNames.size();
		}

		@Override
		public int getColumnCount() {
			return 2;
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {

			String headerName = uniqueHeaderNames.get(rowIndex);
			switch (columnIndex) {
				case 0:
					return headerName;
				case 1:
					return headerValuesMap.get(headerName).iterator().next().value;
				default:
					return "";
			}
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return String.class;
		}

		public List<String> getUniqueHeaderNames() {
			return uniqueHeaderNames;
		}

		public HashMap<String, LinkedHashSet<HeaderValue>> getHeaderValuesMap() {
			return headerValuesMap;
		}
	}
}

