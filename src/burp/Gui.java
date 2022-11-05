package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;

public class Gui {
    public JPanel rootPanel;
    private JTabbedPane tabbedPane;
    private IBurpExtenderCallbacks callbacks;
    private HashMap<Integer, SemScan> semScans;
    private HashMap<Integer, JButton> semActiveBts;
    public Gui(IBurpExtenderCallbacks callbacks){
        this.rootPanel = new JPanel(new GridLayout(1,1));
        this.tabbedPane = new JTabbedPane();
        rootPanel.add(this.tabbedPane);

        this.callbacks = callbacks;
        this.semScans = new HashMap<>();
        this.semActiveBts = new HashMap<>();

        addTab("First tab");
    }
    private void addTab(String title){
        Panel pnlTab = new Panel(new FlowLayout());
        JLabel lblTitle = new JLabel(title);
        lblTitle.addMouseListener(new MouseAdapter()   {
            public void mouseClicked(MouseEvent e)
            {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                    String s = (String)JOptionPane.showInputDialog(
                            e.getComponent(),
                            "Choose a name for the selected tab","Insert tab name:",
                            JOptionPane.PLAIN_MESSAGE,null,null,
                            "");
                    if(!s.equals(""))
                        lblTitle.setText(s);
                }
                for(int i=0; i<tabbedPane.getTabCount(); i++){
                    Panel currComponent = (Panel)tabbedPane.getTabComponentAt(i);
                    if(currComponent.equals(pnlTab)){
                        tabbedPane.setSelectedIndex(i);
                    }
                }
            }
        });

        JLabel lblClose = new JLabel(" x");
        lblClose.addMouseListener(new MouseAdapter()   {
            public void mouseClicked(MouseEvent e)
            {
                for(int i=0; i<tabbedPane.getTabCount(); i++){
                    Panel currComponent = (Panel)tabbedPane.getTabComponentAt(i);
                    if(currComponent.equals(pnlTab)){
                        JButton act = semActiveBts.get(pnlTab.hashCode());
                        if(act.getText()=="Current Semgrepper is on"){
                            act.doClick();
                        }
                        tabbedPane.removeTabAt(i);

                    }
                }
            }
        });
        lblClose.setForeground(Color.gray);
        pnlTab.add(lblTitle);
        pnlTab.add(lblClose);

        removePlusAtEnd();
        tabbedPane.addTab(title, null);
        tabbedPane.setTabComponentAt(tabbedPane.getTabCount()-1,pnlTab);
        addPlusAtEnd();

        createTabContent(tabbedPane.getTabCount()-2);
    }
    private void addPlusAtEnd(){
        JLabel lblAdd = new JLabel("+", SwingConstants.CENTER);
        lblAdd.addMouseListener(new MouseAdapter()   {
            public void mouseClicked(MouseEvent e)
            {
                addTab("New");
            }
        });
        lblAdd.setBorder(new EmptyBorder(2,0,0,0));
        lblAdd.setFont(new Font("Arial", Font.PLAIN, 20));
        lblAdd.setForeground(Color.gray);

        tabbedPane.addTab("Plus", null);
        tabbedPane.setTabComponentAt(tabbedPane.getTabCount()-1,lblAdd);
    }
    private void removePlusAtEnd(){
        if(tabbedPane.getTabCount()==0)
            return;
        JLabel curr = (JLabel)tabbedPane.getTabComponentAt(tabbedPane.getTabCount()-1);
        if(curr != null && curr.getText()=="+")
            tabbedPane.removeTabAt(tabbedPane.getTabCount()-1);
    }
    private void addLeftAligned(JPanel mainElem, JComponent newElem){
        newElem.setAlignmentX(Component.LEFT_ALIGNMENT);
        mainElem.add(newElem);
    }
    private void createTabContent(int idx){
        JPanel pnlMain = new JPanel();
        pnlMain.setLayout(new BoxLayout(pnlMain, BoxLayout.Y_AXIS));
        pnlMain.setBorder(new EmptyBorder(10,10,10,10));
        // Semgrepper ========================================================

        addLeftAligned(pnlMain, createTitle("Semgrepper"));
        addLeftAligned(pnlMain, new JLabel("Use the following button to enable the passive scan checks with the specified settings."));
        addLeftAligned(pnlMain, (JComponent) Box.createVerticalStrut(10));

        JTextArea outTextArea = new JTextArea();
        DefaultTableModel modelPath = new DefaultTableModel();
        modelPath.addColumn("Filepath");
        JTable pathTable = new JTable(modelPath){
            public String getToolTipText(MouseEvent event)
            {
                int col  = convertColumnIndexToModel(columnAtPoint(event.getPoint()));
                int row = convertRowIndexToModel(rowAtPoint(event.getPoint()));
                return (String)modelPath.getValueAt(row,col);
            }
        };
        pathTable.setDefaultEditor(Object.class, null);

        JTable scopeTable = new JTable();

        JButton btnActive = new JButton("Current Semgrepper is off");
        btnActive.setFont(new Font(Font.DIALOG, Font.BOLD, 12));

        semActiveBts.put(tabbedPane.getTabComponentAt(idx).hashCode(), btnActive);

        btnActive.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JButton btnActive = (JButton)e.getSource();
                if(btnActive.getText()=="Current Semgrepper is off"){
                    btnActive.setText("Current Semgrepper is on");
                    btnActive.setBackground(new Color(64, 113, 189));
                    btnActive.setForeground(Color.WHITE);

                    int hash = e.getSource().hashCode();
                    SemScan newSemScan = new SemScan(callbacks, pathTable, scopeTable, outTextArea);
                    semScans.put(hash, newSemScan);
                    callbacks.registerScannerCheck(newSemScan);
                    outTextArea.append("["+hash+"]:"+"SemScan Start\n");
                }else{
                    btnActive.setText("Current Semgrepper is off");
                    btnActive.setBackground(null);
                    btnActive.setForeground(null);
                    int hash = e.getSource().hashCode();
                    callbacks.removeScannerCheck(semScans.get(hash));
                    outTextArea.append("["+hash+"]:"+"SemScan Stop\n");
                }
            }
        });
        addLeftAligned(pnlMain, btnActive);

        addLeftAligned(pnlMain, (JComponent) Box.createVerticalStrut(10));
        addLeftAligned(pnlMain, new JSeparator());

        // Rule Files ===================================
        addLeftAligned(pnlMain, createTitle("Rules Files"));
        addLeftAligned(pnlMain, new JLabel("Use this section to select the files containing the Semgrep rules in YAML format. The preview box can be used to verify the content of the selected rule."));

        JPanel rulePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel ruleAlignPanel = new JPanel();
        ruleAlignPanel.setLayout(new BoxLayout(ruleAlignPanel, BoxLayout.Y_AXIS));
        JPanel ruleTabPanel = new JPanel(new GridLayout());

        rulePanel.add(ruleAlignPanel);
        rulePanel.add(ruleTabPanel);

        JTextArea prevArea = new JTextArea();
        prevArea.setEditable(false);
        JPanel prevPanel = new JPanel();
        JScrollPane prevScroll = new JScrollPane(prevArea);

        pathTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                int row = pathTable.rowAtPoint(evt.getPoint());
                String selectedPath = (String) modelPath.getValueAt(row,0);
                Path filePath = Path.of(selectedPath);
                String fileContent = null;
                try {
                    fileContent = Files.readString(filePath);
                } catch (IOException e) {
                    prevArea.setText("Cannot read the selected file.");
                }
                prevArea.setText(fileContent);
                JScrollBar vertScroll = prevScroll.getVerticalScrollBar();
                vertScroll.setValue(vertScroll.getMinimum());
                JScrollBar horizScroll = prevScroll.getHorizontalScrollBar();
                horizScroll.setValue(horizScroll.getMinimum());
            }
        });

        JFrame multipleFileChooser = new JFrame();
        JButton btnSelect = new JButton("Select");
        btnSelect.setMaximumSize(new Dimension(100,20));
        addWithSpace(ruleAlignPanel, btnSelect);

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setMultiSelectionEnabled(true);
        btnSelect.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int choice = fileChooser.showOpenDialog(multipleFileChooser);
                if (choice == JFileChooser.APPROVE_OPTION) {
                    File[] openFiles = fileChooser.getSelectedFiles();
                    for(File f: openFiles){
                        modelPath.addRow(new String[]{f.getAbsolutePath()});
                    }
                    if(btnActive.getText().equals("Current Semgrepper is on"))
                        btnActive.doClick();
                }
            }
        });

        JButton btnRemove = new JButton("Remove");
        btnRemove.setMaximumSize(new Dimension(100,20));
        addWithSpace(ruleAlignPanel, btnRemove);
        btnRemove.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selected = pathTable.getSelectedRow();
                modelPath.removeRow(selected);
                if(btnActive.getText().equals("Current Semgrepper is on"))
                    btnActive.doClick();
            }
        });

        JButton btnClear = new JButton("Clear");
        btnClear.setMaximumSize(new Dimension(100,20));
        addWithSpace(ruleAlignPanel, btnClear);
        btnClear.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                modelPath.setRowCount(0);
                prevArea.setText("");
                if(btnActive.getText().equals("Current Semgrepper is on"))
                    btnActive.doClick();
            }
        });

        ruleAlignPanel.add(Box.createVerticalStrut(115));

        pathTable.setTableHeader(null);

        JScrollPane pathScrollPane = new JScrollPane(pathTable);
        pathScrollPane.setPreferredSize(new Dimension(500,200));
        JPanel panel = new JPanel();
        panel.add(pathScrollPane);

        ruleTabPanel.add(panel);

        JPanel ruleAlignPanel2 = new JPanel();
        ruleAlignPanel2.setLayout(new BoxLayout(ruleAlignPanel2, BoxLayout.Y_AXIS));
        JLabel prevLabel = new JLabel("Preview:");
        ruleAlignPanel2.add(prevLabel);
        ruleAlignPanel2.add(Box.createVerticalStrut(180));
        rulePanel.add(ruleAlignPanel2);

        prevScroll.getVerticalScrollBar().setValue(0);
        prevScroll.setPreferredSize(new Dimension(400,200));
        prevPanel.add(prevScroll);
        rulePanel.add(prevPanel);

        addLeftAligned(pnlMain, rulePanel);
        addLeftAligned(pnlMain, new JSeparator());

        // Scope =========================================
        addLeftAligned(pnlMain, createTitle("Scope"));
        addLeftAligned(pnlMain, new JLabel("Use these settings to control which responses should be analyzed with Semgrep."));

        JPanel pnlScope = new JPanel(new FlowLayout(FlowLayout.LEFT));

        //JTable scopeTable = new JTable(data2, column2);

        DefaultTableModel modelScope = new DefaultTableModel();
        modelScope.addColumn("Operator");
        modelScope.addColumn("Match type");
        modelScope.addColumn("Relationship");
        modelScope.addColumn("Condition");

        scopeTable.setModel(modelScope);
        scopeTable.getColumnModel().getColumn(0).setPreferredWidth(20);
        scopeTable.getColumnModel().getColumn(1).setPreferredWidth(20);
        scopeTable.getColumnModel().getColumn(2).setPreferredWidth(20);
        scopeTable.getColumnModel().getColumn(3).setPreferredWidth(100);
        scopeTable.setDefaultEditor(Object.class, null);

        JPanel scopeTmpPanel = new JPanel();
        scopeTmpPanel.setLayout(new BoxLayout(scopeTmpPanel, BoxLayout.Y_AXIS));
        JButton btnScopeEdit = new JButton("Edit");
        btnScopeEdit.setMaximumSize(new Dimension(100,20));

        JButton btnScopeRemove = new JButton("Remove");
        btnScopeRemove.setMaximumSize(new Dimension(100,20));
        btnScopeRemove.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selected = scopeTable.getSelectedRow();
                modelScope.removeRow(selected);
                if(btnActive.getText().equals("Current Semgrepper is on"))
                    btnActive.doClick();
            }
        });
        JButton btnScopeClear = new JButton("Clear");
        btnScopeClear.setMaximumSize(new Dimension(100,20));
        btnScopeClear.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                modelScope.setRowCount(0);
                if(btnActive.getText().equals("Current Semgrepper is on"))
                    btnActive.doClick();
            }
        });

        String[] currFields = new String[]{"And", "Response Header", "Contains", ""};

        ActionListener okListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JButton btnSource = (JButton) e.getSource();
                if(btnSource.getText()=="Edit"){
                    int selected = scopeTable.getSelectedRow();
                    currFields[0] = (String)scopeTable.getValueAt(selected, 0);
                    currFields[1] = (String)scopeTable.getValueAt(selected, 1);
                    currFields[2] = (String)scopeTable.getValueAt(selected, 2);
                    currFields[3] = (String)scopeTable.getValueAt(selected, 3);
                }
                JFrame frame = new JFrame();
                frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
                frame.setSize(600,400);
                frame.setTitle("Edit scope rule");
                JPanel m = new JPanel(new BorderLayout());
                JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
                m.setBorder(new EmptyBorder(10,10,10,10));
                p.setBorder(new EmptyBorder(20,20,20,20));
                JPanel lblPanel = new JPanel(new GridLayout(4,1));
                JPanel fieldPanel = new JPanel(new GridLayout(4,1));

                JLabel operLbl = new JLabel("Boolean operator:");
                JLabel typeLbl = new JLabel("Match type:");
                JLabel relatLbl = new JLabel("Match relationship:");
                JLabel matchLbl = new JLabel("Match condition:");
                operLbl.setBorder(new EmptyBorder(3,3,3,3));
                typeLbl.setBorder(new EmptyBorder(3,3,3,3));
                relatLbl.setBorder(new EmptyBorder(3,3,3,3));
                matchLbl.setBorder(new EmptyBorder(3,3,3,3));

                lblPanel.add(operLbl);
                lblPanel.add(typeLbl);
                lblPanel.add(relatLbl);
                lblPanel.add(matchLbl);

                String operCmb[] = { "And", "Or" };
                String typeCmb[] = { "Response Header", "Response Body" };
                String relatCmb[] = { "Contains", "Does not contain" };
                JComboBox operBox = new JComboBox(operCmb);
                JComboBox typeBox = new JComboBox(typeCmb);
                JComboBox relatBox = new JComboBox(relatCmb);
                operBox.setSelectedItem(currFields[0]);
                typeBox.setSelectedItem(currFields[1]);
                relatBox.setSelectedItem(currFields[2]);

                operBox.setPreferredSize(new Dimension(300,20));
                typeBox.setPreferredSize(new Dimension(300,20));
                relatBox.setPreferredSize(new Dimension(300,20));

                fieldPanel.add(operBox);
                fieldPanel.add(typeBox);
                fieldPanel.add(relatBox);
                JTextField valField = new JTextField(currFields[3]);
                fieldPanel.add(valField);

                p.add(lblPanel);
                p.add(fieldPanel);

                m.add(new JLabel("Specify the details of the scope rule."), BorderLayout.PAGE_START);
                m.add(p, BorderLayout.CENTER);
                JButton btnOk = new JButton("Ok");
                if(btnSource.getText().equals("Edit")){
                    btnOk.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            int selected = scopeTable.getSelectedRow();
                            modelScope.setValueAt(operBox.getSelectedItem(), selected, 0);
                            modelScope.setValueAt(typeBox.getSelectedItem(), selected, 1);
                            modelScope.setValueAt(relatBox.getSelectedItem(), selected, 2);
                            modelScope.setValueAt(valField.getText(), selected, 3);

                            frame.dispose();
                            if(btnActive.getText().equals("Current Semgrepper is on"))
                                btnActive.doClick();
                        }
                    });
                }else if(btnSource.getText().equals("Add")){

                    btnOk.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            modelScope.addRow(new String[]{(String) operBox.getSelectedItem(),
                                    (String) typeBox.getSelectedItem(),
                                    (String) relatBox.getSelectedItem(),
                                    valField.getText()
                            });
                            frame.dispose();
                            if(btnActive.getText().equals("Current Semgrepper is on"))
                                btnActive.doClick();
                        }
                    });
                }
                m.add(btnOk, BorderLayout.PAGE_END);
                frame.setContentPane(m);
                frame.pack();
                frame.setLocationRelativeTo(null);
                frame.setVisible(true);
            }
        };
        JButton btnScopeAdd = new JButton("Add");
        btnScopeAdd.setMaximumSize(new Dimension(100,20));

        btnScopeEdit.addActionListener(okListener);
        btnScopeAdd.addActionListener(okListener);

        addWithSpace(scopeTmpPanel, btnScopeEdit);
        addWithSpace(scopeTmpPanel, btnScopeAdd);
        addWithSpace(scopeTmpPanel, btnScopeRemove);
        addWithSpace(scopeTmpPanel, btnScopeClear);
        scopeTmpPanel.add(Box.createVerticalStrut(10));

        pnlScope.add(scopeTmpPanel);

        JScrollPane scopeScrollPane = new JScrollPane(scopeTable);
        scopeScrollPane.setPreferredSize(new Dimension(600,120));
        JPanel pnlTabScope = new JPanel();
        pnlTabScope.add(scopeScrollPane);

        pnlScope.add(pnlTabScope);

        addLeftAligned(pnlMain, pnlScope);

        addLeftAligned(pnlMain, new JSeparator());
        // Output =====================================

        addLeftAligned(pnlMain, createTitle("Error Logs"));
        addLeftAligned(pnlMain, new JLabel("The following panel reports the error logs of the current panel."));


        outTextArea.setText("");
        outTextArea.setEditable(false);

        JScrollPane outScroll = new JScrollPane(outTextArea);
        outScroll.setPreferredSize(new Dimension(outScroll.getWidth(),150));

        addLeftAligned(pnlMain, outScroll);

        JScrollPane mainScroll = new JScrollPane(pnlMain);
        tabbedPane.setComponentAt(idx, mainScroll);
    }
    private static JLabel createTitle(String title){
        JLabel lblTitle = new JLabel(title);

        lblTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
        lblTitle.setForeground(new Color(255,102,51));
        lblTitle.setBorder(new EmptyBorder(5,0,5,5));
        return lblTitle;
    }
    private void addWithSpace(JComponent container, JComponent elem){
        container.add(elem);
        container.add(Box.createRigidArea(new Dimension(5, 5)));
    }

}
