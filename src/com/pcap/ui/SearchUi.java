package com.pcap.ui;

import com.pcap.config.Config;
import com.pcap.model.Packet;
import com.pcap.storage.Storage;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * Basic Swing UI (Level 4) to search processed data by protocol and IP
 * address, and to display aggregated protocol counts.
 */
public final class SearchUi {

    private final Config config;
    private final Storage storage;

    private JFrame frame;
    private JTextField protocolField;
    private JTextField ipField;
    private JTable table;
    private JLabel statusLabel;

    public SearchUi(Config config, Storage storage) {
        this.config = config;
        this.storage = storage;
    }

    public void show() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                buildAndShow();
            }
        });
    }

    private void buildAndShow() {
        frame = new JFrame("PCAP Processor - Search");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Protocol:"));
        protocolField = new JTextField(10);
        top.add(protocolField);
        top.add(new JLabel("IP:"));
        ipField = new JTextField(14);
        top.add(ipField);

        JButton search = new JButton("Search");
        search.addActionListener(e -> doSearch());
        top.add(search);
        JButton counts = new JButton("Protocol Counts");
        counts.addActionListener(e -> showCounts());
        top.add(counts);

        table = new JTable(new DefaultTableModel(
                new Object[]{"Index", "Time", "Protocol", "Src IP", "Dst IP", "Src Mac", "Dst Mac", "SrcPort", "DstPort", "Host", "URI"}, 0));
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        statusLabel = new JLabel("Ready");
        frame.getContentPane().setLayout(new BorderLayout());
        frame.getContentPane().add(top, BorderLayout.NORTH);
        frame.getContentPane().add(new JScrollPane(table), BorderLayout.CENTER);
        frame.getContentPane().add(statusLabel, BorderLayout.SOUTH);

        frame.setSize(1000, 500);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private void doSearch() {
        String protocol = protocolField.getText().trim();
        String ip = ipField.getText().trim();
        try {
            List<Packet> results = storage.search(protocol, ip, 500);
            DefaultTableModel model = (DefaultTableModel) table.getModel();
            model.setRowCount(0);
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            for (Packet p : results) {
                model.addRow(new Object[]{
                        p.index,
                        sdf.format(new Date(p.timestampMs)),
                        p.protocol,
                        p.srcIp,
                        p.dstIp,
                        p.srcMac,
                        p.dstMac,
                        p.srcPort < 0 ? "" : p.srcPort,
                        p.dstPort < 0 ? "" : p.dstPort,
                        p.httpHost,
                        p.httpUri
                });
            }
            statusLabel.setText(results.size() + " results");
        } catch (Exception e) {
            statusLabel.setText("Error: " + e.getMessage());
        }
    }

    private void showCounts() {
        try {
            java.util.Map<String, Long> counts = storage.protocolCounts();
            DefaultTableModel model = (DefaultTableModel) table.getModel();
            model.setRowCount(0);
            model.setColumnIdentifiers(new Object[]{"Protocol", "Count"});
            for (java.util.Map.Entry<String, Long> e : counts.entrySet()) {
                model.addRow(new Object[]{e.getKey(), e.getValue()});
            }
            statusLabel.setText(counts.size() + " protocols");
        } catch (Exception e) {
            statusLabel.setText("Error: " + e.getMessage());
        }
    }
}
