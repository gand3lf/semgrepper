package burp;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.Map;
import org.json.*;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static final String author = "Riccardo Cardelli @gand3lf";
    public static final String SEMDIR = "SemgrepBurpPlugin";
    public static final String CACHEFILE = ".cachePlugin";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        JSONObject j=new JSONObject("{}");

        callbacks.setExtensionName("Semgrepper");

        boolean semgrepInstalled = true;

        ProcessBuilder processBuilder = new ProcessBuilder();
        Map<String, String> envs = processBuilder.environment();

        String[] semgrepCmd = new String[]{};
        if(Utils.getOperatingSystem() == Utils.OS.WINDOWS){
            if(Utils.exec(new String[]{"wsl", "semgrep", "--version"}) == 0)
                semgrepCmd = new String[]{"wsl", "semgrep"};
        }else if(Utils.getOperatingSystem() == Utils.OS.LINUX){

        }else if(Utils.getOperatingSystem() == Utils.OS.MAC){
            if(Utils.exec(new String[]{"/opt/homebrew/bin/semgrep", "--version"}) == 0)
                semgrepCmd = new String[]{"/opt/homebrew/bin/semgrep"};
            else if(Utils.exec(new String[]{"/usr/local/bin/semgrep", "--version"}) == 0)
                semgrepCmd = new String[]{"/usr/local/bin/semgrep"};
        }

        if(semgrepCmd.length == 0 && Utils.exec(new String[]{"semgrep", "--version"}) == 0){
            semgrepCmd = new String[]{"semgrep"};
        }

        if(semgrepCmd.length == 0)
            semgrepInstalled = false;

        if(semgrepInstalled) {
            SemScan.semgrepCmd = semgrepCmd;
            File theDir = new File(System.getProperty("java.io.tmpdir") + "/" + BurpExtender.SEMDIR);
            if (!theDir.exists()) {
                theDir.mkdirs();
            }

            Tab mainTab = new Tab(new Gui(callbacks).rootPanel);
            callbacks.addSuiteTab(mainTab);
        }else{
            JPanel errPanel = new JPanel();
            String msg = "\nIt seems that you don't have Semgrep installed!\n\nPlease, follow these instructions to install it:\n";
            msg += " • Ubuntu, Windows through Windows Subsystem for Linux (WSL), Linux, macOS:\n     python3 -m pip install semgrep\n";
            msg += " • macOS:\n     brew install semgrep";
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
            if(!currentFile.getPath().contains(CACHEFILE))
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
