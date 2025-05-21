package burp;

import org.json.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

class CustomScanIssue implements IScanIssue{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    private final IHttpRequestResponseWithMarkers markedRequestResponse;

    public CustomScanIssue(
            IBurpExtenderCallbacks callbacks,
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
            int bodyOffset)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;


        JSONObject obj = new JSONObject(this.detail);
        JSONArray objArr = obj.getJSONArray("results");
        List<int[]> responseMarkers = new ArrayList<>();

        for(int i=0; i< objArr.length(); i++){
            JSONObject currObj = objArr.getJSONObject(i);

            int startOffset = Integer.parseInt(currObj.getJSONObject("start").get("offset").toString());
            int endOffset = Integer.parseInt(currObj.getJSONObject("end").get("offset").toString());
            
            responseMarkers.add(new int[]{startOffset + bodyOffset, endOffset + bodyOffset});
        }

        this.markedRequestResponse = callbacks.applyMarkers(
            httpMessages[0],
            null,
            responseMarkers
        );
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
        String body = "";

        JSONObject obj = new JSONObject(this.detail);
        JSONArray objArr = obj.getJSONArray("results");
        for(int i=0; i< objArr.length(); i++){
            JSONObject currObj = objArr.getJSONObject(i);

            String startLine = currObj.getJSONObject("start").get("line").toString();
            String endLine = currObj.getJSONObject("end").get("line").toString();

            body += "<b>File:</b> " + currObj.get("path") + " [" + startLine + ", " + endLine + "]<br>";
            
            String[] checkIDRaw = currObj.get("check_id").toString().split("\\.");
            if(checkIDRaw.length > 0){
                String checkID = checkIDRaw[checkIDRaw.length - 1];
                body += "<b>Rule ID:</b> " + checkID + "<br>";
            }else{
                body += "<b>Rule ID:</b> " + currObj.get("check_id").toString() + "<br>";
            }
            JSONObject extraObj = currObj.getJSONObject("extra");
            String currMessage = extraObj.get("message").toString();
            body += "<b>Message</b>:<br><i>" + currMessage + "</i><br><br>";

            /*
            String lines = extraObj.get("lines").toString();
            lines = lines.replace(" ", "&#x20;");
            lines = lines.replace("\t","&#x20;&#x20;&#x20;&#x20;");
            lines = lines.replace("\n", "<br>");
            body += "<b>Lines</b>:<br><i>" + lines + "</i><br><br>";
            */
        }
        // OLD SECTION
        /* 
        JSONObject obj = new JSONObject(this.detail);
        JSONArray objArr = obj.getJSONArray("vulnerabilities");
        for(int i=0; i< objArr.length(); i++){
            JSONObject currObj = objArr.getJSONObject(0);
            String currMessage = currObj.get("message").toString();
            JSONObject currLocation = currObj.getJSONObject("location");
            String currStart = currLocation.get("start_line").toString();
            String currEnd = currLocation.get("end_line").toString();
            String currFile = currLocation.get("file").toString();

            JSONArray currCode = currObj.getJSONArray("raw_source_code_extract");
            String bodyCode = "";
            for(int j=0, k=Integer.parseInt(currStart);j<currCode.length();j++,k++){
                int pad = currEnd.length() - Integer.toString(k).length();
                String padS = new String(new char[pad]).replace("\0", "&ensp;");

                bodyCode += padS + k + "|&#x20;<i>" + Utils.htmlEncode(currCode.get(j).toString()) + "</i>";
            }

            bodyCode = bodyCode.replace(" ", "&#x20;");
            bodyCode = bodyCode.replace("\t","&#x20;&#x20;&#x20;&#x20;");
            bodyCode = bodyCode.replace("\n", "<br>");

            body += "<b>File:</b> " + currFile + " (<i>line: " + currStart + "-" + currEnd + "</i>)<br>";
            body += "<b>Message</b>: " + currMessage  + "<br>";
            body += "<b>Source code extract</b>:<br>" + bodyCode  + "<br><br>";

        }*/

        return body;
    }

    public String getIssueCode(){
        return "";
    }
    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return new IHttpRequestResponse[] { markedRequestResponse };
        //IHttpRequestResponse m = markedRequestResponse;
        //return {m};
        //return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }

}
