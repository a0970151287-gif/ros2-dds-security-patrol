[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Get-SafeDefenderStatus {
    try {
        $status = Get-MpComputerStatus
        return [ordered]@{
            available                  = $true
            antivirus_enabled          = [bool]$status.AntivirusEnabled
            antispyware_enabled        = [bool]$status.AntispywareEnabled
            real_time_protection       = [bool]$status.RealTimeProtectionEnabled
            behavior_monitor           = [bool]$status.BehaviorMonitorEnabled
            network_inspection         = [bool]$status.NISEnabled
            signatures_last_updated_utc = if ($status.AntivirusSignatureLastUpdated) {
                $status.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')
            } else {
                $null
            }
        }
    } catch {
        return [ordered]@{
            available = $false
            error     = $_.Exception.Message
        }
    }
}

$profiles = Get-NetFirewallProfile | ForEach-Object {
    [ordered]@{
        name                    = $_.Name
        enabled                 = [bool]$_.Enabled
        default_inbound_action  = $_.DefaultInboundAction.ToString()
        default_outbound_action = $_.DefaultOutboundAction.ToString()
    }
}

$processNames = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $processNames[[int]$_.Id] = $_.ProcessName
}

$listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Sort-Object LocalPort, LocalAddress |
    ForEach-Object {
        [ordered]@{
            address = $_.LocalAddress
            port    = [int]$_.LocalPort
            process = $processNames[[int]$_.OwningProcess]
        }
    }

$netshPolicy = (& netsh.exe advfirewall show allprofiles 2>&1 | Out-String).Trim()
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

[ordered]@{
    schema_version = 'sros2-windows-defense-snapshot/v1'
    generated_utc  = [DateTime]::UtcNow.ToString('o')
    elevated       = $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    firewall       = [ordered]@{
        profiles    = @($profiles)
        netsh_policy = $netshPolicy
    }
    defender       = Get-SafeDefenderStatus
    tcp_listeners  = @($listeners)
} | ConvertTo-Json -Depth 7
