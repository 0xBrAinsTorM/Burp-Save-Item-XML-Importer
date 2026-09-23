package com.secianus.burpxml;

import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.http.HttpService.httpService;
import static burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;
import static burp.api.montoya.http.message.responses.HttpResponse.httpResponse;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ExecutionException;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingWorker;
import javax.swing.filechooser.FileNameExtensionFilter;

/** Montoya extension entry point. */
public final class BurpXmlImporterExtension implements BurpExtension {
    private MontoyaApi api;
    private JPanel panel;
    private JButton importButton;
    private JTextArea output;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Burp Save Item XML Importer");
        buildUi();
        api.userInterface().applyThemeToComponent(panel);
        api.userInterface().registerSuiteTab("Save Item XML Importer", panel);
        api.logging().logToOutput("Burp Save Item XML Importer loaded; no requests are sent by this extension.");
    }

    private void buildUi() {
        panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JLabel description = new JLabel("Import trusted Burp Save item(s) XML into Target > Site map. "
                + "Stored requests are never sent.");
        panel.add(description, BorderLayout.NORTH);

        output = new JTextArea(14, 90);
        output.setEditable(false);
        output.setLineWrap(true);
        output.setWrapStyleWord(true);
        output.setText("Ready. Select a Burp XML export.\n");
        panel.add(new JScrollPane(output), BorderLayout.CENTER);

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        importButton = new JButton("Import Burp XML");
        importButton.addActionListener(event -> chooseAndImport());
        controls.add(importButton);
        panel.add(controls, BorderLayout.SOUTH);
    }

    private void chooseAndImport() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Burp Save item(s) XML");
        chooser.setFileFilter(new FileNameExtensionFilter("Burp XML files (*.xml)", "xml"));
        chooser.setAcceptAllFileFilterUsed(false);
        if (chooser.showOpenDialog(panel) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        Path selected = chooser.getSelectedFile().toPath();
        importButton.setEnabled(false);
        output.append("\nParsing " + selected.getFileName() + "...\n");

        new SwingWorker<ImportSummary, Void>() {
            @Override
            protected ImportSummary doInBackground() throws Exception {
                List<BurpItem> items = new BurpXmlParser().parse(selected);
                int imported = 0;
                StringBuilder errors = new StringBuilder();
                for (int i = 0; i < items.size(); i++) {
                    try {
                        addToSiteMap(items.get(i));
                        imported++;
                    } catch (RuntimeException e) {
                        errors.append("Item ").append(i + 1).append(": ")
                                .append(safeMessage(e)).append('\n');
                    }
                }
                return new ImportSummary(items.size(), imported, errors.toString());
            }

            @Override
            protected void done() {
                importButton.setEnabled(true);
                try {
                    ImportSummary summary = get();
                    output.append("Imported " + summary.imported + " of " + summary.total
                            + " item(s) into Target > Site map.\n");
                    if (!summary.errors.isEmpty()) {
                        output.append(summary.errors);
                    }
                    output.append("No HTTP requests were sent. Matching Site Map entries may have been replaced.\n");
                    api.logging().logToOutput("Burp XML import completed: " + summary.imported
                            + "/" + summary.total + " item(s)");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    output.append("Import interrupted.\n");
                } catch (ExecutionException e) {
                    Throwable cause = e.getCause() == null ? e : e.getCause();
                    output.append("Import rejected: " + safeMessage(cause) + "\n");
                    api.logging().logToError("Burp XML import rejected", cause);
                }
            }
        }.execute();
    }

    private void addToSiteMap(BurpItem item) {
        HttpRequest request = httpRequest(
                httpService(item.host(), item.port(), item.secure()),
                byteArray(item.request()));
        HttpResponse response = item.hasResponse() ? httpResponse(byteArray(item.response())) : null;
        HttpRequestResponse pair = httpRequestResponse(request, response);
        api.siteMap().add(pair);
    }

    private static String safeMessage(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.isBlank() ? throwable.getClass().getSimpleName() : message;
    }

    private static final class ImportSummary {
        private final int total;
        private final int imported;
        private final String errors;

        private ImportSummary(int total, int imported, String errors) {
            this.total = total;
            this.imported = imported;
            this.errors = errors;
        }
    }
}
