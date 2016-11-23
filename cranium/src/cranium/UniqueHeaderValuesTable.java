package cranium;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

class UniqueHeaderValuesTable extends JTable {

	private final UniqueHeaderValuesTableModel model;
	private final MessageEditor messageEditor;

	UniqueHeaderValuesTable(MessageEditor messageEditor) {
		super();
		model = new UniqueHeaderValuesTableModel();
		this.setModel(model);
		this.messageEditor = messageEditor;
	}

	void setHeaderValues(ArrayList<HeaderValue> headerValues) {
		model.setHeaderValues(headerValues);
		model.fireTableDataChanged();
	}

	@Override
	public void changeSelection(int row, int col, boolean toggle, boolean extend) {
		HeaderValue headerValue = model.getHeaderValues().get(row);
		messageEditor.setCurrentlyDisplayedItem(headerValue.requestResponse);

		super.changeSelection(row, col, toggle, extend);
	}


	private static class UniqueHeaderValuesTableModel extends AbstractTableModel {

		private ArrayList<HeaderValue> headerValues = new ArrayList<>();

		ArrayList<HeaderValue> getHeaderValues() {
			return headerValues;
		}

		void setHeaderValues(ArrayList<HeaderValue> headerValues) {
			this.headerValues = headerValues;
		}

		@Override
		public int getRowCount() {
			return headerValues.size();
		}

		@Override
		public int getColumnCount() {
			return 1;
		}

		@Override
		public String getColumnName(int columnIndex) {
			switch (columnIndex) {
				case 0:
					return "Value";
				default:
					return "";
			}
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return String.class;
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			String value = headerValues.get(rowIndex).value;

			switch (columnIndex) {
				case 0:
					return value;
				default:
					return "";
			}
		}
	}

}
