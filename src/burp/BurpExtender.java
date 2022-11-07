package burp;

import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.security.cert.Extension;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private String author = "Riccardo Cardelli @gand3lf";
    public static final String SEMDIR = "SEMDIR_BURP_PLUGIN";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IScannerCheck SemScan;
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Semgrepper");

        boolean semgrepInstalled = true;

        ProcessBuilder processBuilder = new ProcessBuilder();
        List<String> cmdParam = new ArrayList<>();
        cmdParam.add("semgrep");
        cmdParam.add("--version");
        processBuilder.command(cmdParam);
        try {
            Process process = processBuilder.start();
            StringBuilder output = new StringBuilder();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            int exitVal = process.waitFor();
            if(exitVal != 0)
                semgrepInstalled = false;
        }catch(Exception e){
            semgrepInstalled = false;
        }

        if(semgrepInstalled) {
            File theDir = new File(System.getProperty("java.io.tmpdir") + "/" + BurpExtender.SEMDIR);
            if (!theDir.exists()) {
                theDir.mkdirs();
            }

            Tab mainTab = new Tab(new Gui(callbacks).rootPanel);
            callbacks.addSuiteTab(mainTab);
        }else{
            JPanel errPanel = new JPanel();
            errPanel.add(new JLabel("Semgrep is required to use this extension."));
            Tab mainTab = new Tab(errPanel);
            callbacks.addSuiteTab(mainTab);
        }
    }
    @Override
    public void extensionUnloaded() {
        File theDir = new File(System.getProperty("java.io.tmpdir") + "/" + BurpExtender.SEMDIR);
        String[] entries = theDir.list();
        for(String s: entries){
            File currentFile = new File(theDir.getPath(), s);
            currentFile.delete();
        }
    }
    class Tab implements ITab{
        private Component mainTab;
        public Tab(Component mainTab){
            super();
            this.mainTab = mainTab;
        }
        @Override
        public String getTabCaption() {
            return "Semgrepper";
        }
        @Override
        public Component getUiComponent() {
            return mainTab;
        }
    }


}
