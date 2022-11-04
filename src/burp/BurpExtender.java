package burp;

import java.awt.*;
import java.io.File;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private String author = "Riccardo Cardelli @gand3lf";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IScannerCheck SemScan;
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Semgrepper");
        File theDir = new File(System.getProperty("java.io.tmpdir") + "/" + CommonString.SEMDIR);
        if (!theDir.exists()){
            theDir.mkdirs();
        }

        Tab myTab = new Tab();
        callbacks.addSuiteTab(myTab);
        }

    @Override
    public void extensionUnloaded() { // NON VIENE CHIAMATO
        File theDir = new File(System.getProperty("java.io.tmpdir") + "/" + CommonString.SEMDIR);
        String[]entries = theDir.list();
        for(String s: entries){
            File currentFile = new File(theDir.getPath(), s);
            currentFile.delete();
        }
    }

    class Tab implements ITab{
        @Override
        public String getTabCaption() {
            return "Semgrepper";
        }
        @Override
        public Component getUiComponent() {
            return new Gui(callbacks).rootPanel;
        }
    }


}
