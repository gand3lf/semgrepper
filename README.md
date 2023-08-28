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

## Tutorial

1. Add the Semgrepper extension to Burp Suite.
2. From the section "Rules Files", select the Semgrep rules you want to use.
![rulesfiles](https://github.com/tghosth/semgrepper/assets/18307497/e0629c82-0ec3-4311-b12f-dc9ae4310a3c)
3. From the section "Scope", it is possible to configure some constraints to apply or not a rule to a specific response.  
![scope](https://github.com/tghosth/semgrepper/assets/18307497/a16f6b1c-1f70-4678-b9fe-7e9663fc7c94)
4. Enable the rules by toggling the button "Current Semgrepper is off/on".  
![semgrepperbutton](https://github.com/tghosth/semgrepper/assets/18307497/1490522d-3512-4e2a-9ee4-36e732f650a8)
5. Passively scan the target host. 

## Special thanks

* [Giovanni Fazi](https://github.com/giovifazi)

## Current status ##

| License | Compatibility |
|---|---|
| [![GNU v3](https://img.shields.io/badge/license-GPL-green.svg)](https://github.com/Gand3lf/heappy/blob/main/LICENSE) | [![Python 3](https://img.shields.io/badge/burpsuite-2023-orange)](https://portswigger.net/burp) |
