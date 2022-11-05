# :arrow_forward: Semgrepper 
The current project provides a Burp Suite extension to allow users to include Semgrep results to extend the checks in use by the passive scanner. 
By visiting repositories that collect Semgrep rules, it is possible to verify the large number of rules related to the front-end environment written by the community, such as: https://github.com/returntocorp/semgrep-rules/tree/develop/javascript.

By using this plugin, Burp Suite users can include the Semgrep rules YAML files and define the scope of the analysis, as shown in the following screenshot:

![semgrepper2](https://user-images.githubusercontent.com/18307497/200126200-d91e474a-b079-46f3-9171-06c2ed80e124.png)

## Main features
This is what Semgrepper implements:  
&nbsp;&nbsp; :heavy_check_mark: multiple tabs to use different Semgrep rules with different scopes  
&nbsp;&nbsp; :heavy_check_mark: select files or directories containing Semgrep rules in YAML format  
&nbsp;&nbsp; :heavy_check_mark: define a scope by specifing what can be or not be present in the response header/body  
&nbsp;&nbsp; :heavy_check_mark: deactivate the checks without unloading the plugin  

## Prerequisites
The plugin needs that Semgrep CLI is installed in your machine.  
Please, follow these instructions to install Semgrep:
* For Ubuntu, Windows through Windows Subsystem for Linux (WSL), Linux, macOS
  >python3 -m pip install semgrep

* For macOS
  >brew install semgrep

## Current status ##

| License | Compatibility |
|---|---|
| [![GNU v3](https://img.shields.io/badge/license-GPL-green.svg)](https://github.com/Gand3lf/heappy/blob/main/LICENSE) | [![Python 3](https://img.shields.io/badge/burpsuite-2022-orange)](https://portswigger.net/burp) |
