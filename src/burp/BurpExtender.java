package burp;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static final String author = "Riccardo Cardelli @gand3lf";
    public static final String SEMDIR = "SEMDIR_BURP_PLUGIN";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Semgrepper");

        boolean semgrepInstalled = true;

        ProcessBuilder processBuilder = new ProcessBuilder();
        Map<String, String> envs = processBuilder.environment();

        if(envs.keySet().contains("__CFBundleIdentifier")){
            //MacOS
            processBuilder.command("/opt/homebrew/bin/semgrep", "--version");
        }else {
            processBuilder.command("semgrep", "--version");
        }
        
        try {
            Process process = processBuilder.start();
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
            String msg = "\nIt seems that you don't have Semgrep installed!\n\nPlease, follow these instructions to install it:\n";
            msg += " - Ubuntu, Windows through Windows Subsystem for Linux (WSL), Linux, macOS:\n     python3 -m pip install semgrep\n";
            msg += " - macOS:\n     brew install semgrep";
            JTextArea textArea = new JTextArea(msg);
            textArea.setBorder(null);
            textArea.setEditable(false);
            textArea.setForeground(Color.darkGray);
            errPanel.add(textArea);
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
