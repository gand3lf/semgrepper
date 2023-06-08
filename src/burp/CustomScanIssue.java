package burp;

import org.json.*;
import java.net.URL;

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
        String body = "";

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

        }

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
