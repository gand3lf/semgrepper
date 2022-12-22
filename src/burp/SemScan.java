package burp;

import javax.swing.*;
import java.io.*;
import java.net.URL;
import java.util.*;
import java.util.List;

public class SemScan implements IScannerCheck{
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private JTable scopeTab;
    private List<String> pathString;
    private HashMap<String, Boolean> scopeInfo;
    private JTextArea outArea;
    public SemScan(IBurpExtenderCallbacks callbacks, JTable pathTab, JTable scopeTab, JTextArea outArea){
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.scopeTab = scopeTab;
        this.outArea = outArea;

        this.pathString = new ArrayList<>();
        for(int i=0; i<pathTab.getRowCount(); i++){
            pathString.add((String)pathTab.getValueAt(i, 0));
        }

        this.scopeInfo = scopeAnalyze();
    }
    private String writeInTmpFile(String content){
        String tmpdir = System.getProperty("java.io.tmpdir") + "/" + BurpExtender.SEMDIR;
        byte[] array = new byte[32];
        new Random().nextBytes(array);
        String filepath = tmpdir + "/" + Base64.getEncoder().encodeToString(array).replace("/","_");

        try {
            FileWriter fw = new FileWriter(filepath);
            fw.write(content);
            fw.close();
            return filepath;
        } catch (Exception e) {
            return e.toString();
        }
    }
    private String semgrepLaunch(List<String> rules, String filepath){
        ProcessBuilder processBuilder = new ProcessBuilder();
        List<String> cmdParam = new ArrayList<>();
        cmdParam.add("semgrep");
        for(String rulePath:rules){
            String tmpLower = rulePath.toLowerCase();
            if( !rulePath.matches("[&;`|\"]+") && (tmpLower.endsWith(".yaml") || tmpLower.endsWith(".yml"))){
                cmdParam.add("--config");
                cmdParam.add(rulePath);
            }
        }
        cmdParam.add(filepath);
        //cmdParam.add("--emacs");

        processBuilder.command(cmdParam);

        try {
            Process process = processBuilder.start();
            StringBuilder output = new StringBuilder();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader readerErr = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line + "\n");
            }
            String errLine;
            while ((errLine = readerErr.readLine()) != null) {
                outArea.append(errLine + "\n");
            }
            int exitVal = process.waitFor();
            return output.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "Semgrep Error";
    }
    private String analyzeResponse(String body, String path){
        String tmpFile = writeInTmpFile(body);

        String res = semgrepLaunch(this.pathString, tmpFile);
        outArea.append(res);
        File f= new File(tmpFile);
        f.delete();

        return res.replace(tmpFile, path);
    }
    private HashMap<String, Boolean> scopeAnalyze(){
        HashMap<String, Boolean> ret = new HashMap<>();

        boolean bodyRequested = false;
        boolean headerRequested = false;
        for(int i=0; i<scopeTab.getRowCount(); i++) {
            String match = scopeTab.getValueAt(i,1).toString();
            headerRequested = headerRequested || match.equals("Response Header");
            bodyRequested = bodyRequested || match.equals("Response Body");
        }
        ret.put("bodyRequested", bodyRequested);
        ret.put("headerRequested", headerRequested);
        return ret;
    }
    private boolean isInScope(IHttpRequestResponse baseRequestResponse){
        List<String> headers = null;
        String body = null;
        if(scopeInfo.get("headerRequested")){
            headers = helpers.analyzeResponse(baseRequestResponse.getResponse()).getHeaders();
        }
        if(scopeInfo.get("bodyRequested")){
            byte[] rawResp =  baseRequestResponse.getResponse();
            int bodyOffset = helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset();
            body = helpers.bytesToString(rawResp).substring(bodyOffset);
        }
        if(scopeTab.getRowCount() == 0)
            return false;

        boolean res = true;
        for(int i=0; i<scopeTab.getRowCount(); i++){
            String operator = scopeTab.getValueAt(i,0).toString();
            String match = scopeTab.getValueAt(i,1).toString();
            String relat = scopeTab.getValueAt(i,2).toString();
            String condition = scopeTab.getValueAt(i,3).toString();

            boolean tmp = false;
            if(match.equals("Response Header")){
                for (String s: headers)
                    tmp = tmp || s.contains(condition);
                if(relat.equals("Does not contain"))
                    tmp = !tmp;
            }else{
                if(relat.equals("Contains")){
                    tmp = (body.contains(condition)) ? true : false;
                }else{
                    tmp = (body.contains(condition)) ? false : true;
                }
            }
            if(operator.equals("And")){
                res = res && tmp;
            }else{
                res = res || tmp;
            }
        }
        return res;
    }
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        byte[] request = baseRequestResponse.getRequest();
        byte[] response = baseRequestResponse.getResponse();
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse.getHttpService(), request);
        IResponseInfo responseInfo = helpers.analyzeResponse(response);

        if(isInScope(baseRequestResponse)) {

            int bodyOffset = responseInfo.getBodyOffset();
            String responseBody = helpers.bytesToString(response).substring(bodyOffset);

            String semRes = analyzeResponse(responseBody, requestInfo.getUrl().getPath());
            if(!semRes.equals("")) {

                List<IScanIssue> issues = new ArrayList<>(1);

                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        new IHttpRequestResponse[]{baseRequestResponse},
                        "Semgrep findings",
                        semRes,
                        "Medium"));
                return issues;
            }
        }
        return null;
    }
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()) ? -1 : 0;
    }
}
class CustomScanIssue implements IScanIssue{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Firm";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        String body = this.detail.replace("┆","|");
        body = body.replace("⋮",":");
        body = body.replace("<","&#x3c;");
        body = body.replace(">","&#x3e;");
        body = body.replace("\n","<br>");
        return body;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }

}