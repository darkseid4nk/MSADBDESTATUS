<#
.SYNOPSIS
    Gets bitlocker status of domain computers.

.DESCRIPTION
    Gets bitlocker status of domain computers from both DHCP and a file.txt
    Script arguments should use 3 letter codes from TP naming convention.

    OUTPUT FILES - OUTPUT DESCRIPTION
    # NEED TO WORK ON: errors.txt   - Lists devices we could not get bitlocker status from and why
    missing.txt  - Lists only the devices from errors.txt that can be imported with the -file parameter.
    results.csv  - csv file with the device name, bitlocker encryption method, and date. 
    file.jpg     - screenshots of each device bitlocker status to be used for evidence.

    List of location codes:
    "ALB","ANT","AUG","AUR","AYA","BAC","BAG","BCR","BOS",
    "BRI","BRV","BUR","CAV","CDO","CEB","CIP","COL","CPZ",
    "DAL","DAV","EAG","EAS","EDN","EDS","ELP","FMT","FRB",
    "FTL","FVT","FVW","FWA","GIG","GSN","GUR","GUY","HOB",
    "IDR","JAM","JOP","JPR","KIL","LAO","LOU","LVS","MAH",
    "MAK","MAN","MAR","MAU","MCA","MCK","MKL","MOH","MON",
    "MUR","NIN","OAK","OCT","OGD","ORL","PAN","PAS","PDR",
    "POR","PSL","PWH","RBC","REM","REN","RIC","SAN","SDG",
    "SHR","SLV","SRV","STP","STR","SUC","TOR","TRE","VTS",
    "WAH","WBL","WSM","WVL"

    List of client/special codes:

    "AAC","ABB","ABI","ABT","ACO","ADI","ADO","ADS","ADV","AEO","AFP","AGA","AGI","AIQ","AIZ","AJB","ALC",
    "ALP","ALS","AMT","AMX","AMZ","ANN","AOS","APL","APO","APR","ASR","ASU","ATT","AVA","AVH","AVS","AXP","B2X","BAR","BBS",
    "BBY","BCB","BCM","BCS","BCO","BCP","BDO","BEL","BGT","BHC","BHN","BIC","BIS","BMG","BKG","BKT","BLC","BLG","BLH","BMW",
    "BOA","BOM","BPI","BSC","BSE","BSL","BTU","BVT","BWN","BYR","BZE","CAE","CAI","CAM","CAP","CAR","CBA","CBK","CBS","CCL",
    "CDS","CEN","CFX","CGO","CHS","CHT","CIT","CKM","CLA","CLE","CLR","CLV","CMP","CNH","COB","COM","CON","CCI","COX","CPA",
    "CPL","CRK","CRR","CRT","CSC","CTN","CTO","CTP","CTR","CVA","CVS","CWS","CXL","CYV","DCT","DDP","DEX","DJO","DOD","DRB",
    "DSG","DSH","DSY","DTL","DTO","DTV","DUB","DWI","EAR","EBH","ECH","EEG","EFX","EGE","EHI","EHT","ENR","EPI","EPS","ETR",
    "ESA","EXN","EXP","EXS","FBK","FCA","FCB","FCD","FDR","FDX","FEM","FHR","FIS","FLB","FLI","FLK","FLN","FMT","FOS","FOX",
    "FRC","FRN","FRW","FTD","GDD","GFS","GGL","GHB","GHP","GIB","GLB","GLO","GMC","GMY","GPF","GSK","GTC","GTG","GUT","GVB",
    "HAL","HBI","HCS","HDF","HDP","HDY","HHL","HHS","HIL","HIQ","HLF","HNS","HNT","HOA","HOC","HOE","HOP","HOR","HOT","HPR",
    "HRB","HRC","HRT","HSA","HUA","HUM","HYT","sure","ICM","IDE","IDR","IGM","IKA","INS","INV","IOW","ITS","JLR","JPK","JPM",
    "KCH","KIW","KMS","KOL","KGN","KUR","KUS","LAV","LAZ","LBR","LBU","LCI","LFT","LIB","LIF","LPC","LTR","LTV","MAE","MAS",
    "MAU","MBS","MCP","MDA","MDI","MDS","MDT","MER","MHE","MIC","MJN","MNT","MOL","MON","MSH","MTX","MXC","NAV","NCL","NER",
    "NEX","NFX","NHI","NJM","NKE","NOK","NTA","NXA","NYL","NYT","NYU","OCN","OHL","ORB","OSL","PAM","PCB","PEA","PGX","PHL",
    "PLD","PLI","PMI","PNG","PNI","PPH","PPJ","PPS","PRC","PRO","PRU","PSC","PTC","QND","RBB","RBH","ROB","RBK","RCB","RDG",
    "REB","RFC","RKT","RNG","ROG","RSS","SAM","SAN","SBX","SCT","SDC","SEG","SFA","SFI","SGC","SGE","SGP","SGS","SHK","SHP",
    "SIA","SKM","SLM","SMC","SMG","SMT","SNY","SOS","SPA","SPF","SPK","SPR","SPT","SSE","SSF","STF","STK","STM","SUN","SUP",
    "SWI","SXM","SYM","TEL","TFC","TFS","TGT","TIK","TIM","TLN","TMB","TMC","TMI","TOS","TPF","TMU","TRS","TRU","TUR","TWC",
    "TXU","TZL","UAA","UAM","UBR","UHC","UNC","USB","UST","UVB","VAC","VER","VFS","VGO","VID","VOD","VON","VOW","VOY","VSH",
    "VST","VWG","VZW","WAG","WIN","WLC","WMT","WOP","WTP","WTR","WUN","WWG","WYN","XIA","YCA","YGC","YHO","YLE","ZAL","ZLW"
    "ADM","CLT","ITD","LAP","MUL","QAS","TRN","WFM"

.PARAMETER FilterVLAN
    Parameter not used with -nodhcp, Use 3 letter center id
    Filter available VLANs returned from DHCP server. ex: "NIN"
    would return NIN-VLAN-201, NIN-VLAN-203, etc

.PARAMETER FilterDevice
    ex: "rem-lap" - will filter devices from file.txt and DHCP Leases to only return those that start with "rem-lap*"

    This should always use the format CenterID-ClientID. Center and Client IDs listed in description.

.PARAMETER File
    /path/to/file.txt - Text file list of computer names, one per line.

.PARAMETER nodhcp
    Flag to skip dhcp lease lookup.

.EXAMPLE
    blstat2.ps1 -filtervlan 'NIN' -filterdevice 'rem-lap'

    Collects all active leases and reservations for devices from VLAN NIN that have hostnames starting with REM-LAP
    Returns bitlocker status.

.EXAMPLE
    blstat2.ps1 -filtervlan 'NIN' -filterdevice 'rem-lap' -file laptops.txt

    Collects all active leases and reservations for devices from VLAN NIN that have hostnames starting with REM-LAP.
    Includes computers from laptops.txt with the list retrieved from DHCP server.
    Returns bitlocker status.

.EXAMPLE
    blstat2.ps1 -nodhcp -file laptops.txt

    Returns bitlocker status of all devices listed in laptops.txt, skips gathering devices from DHCP, skips device filtering.

#>

#Set script params
param(
    [String]$filtervlan,
    $filterdevice, 
    $file, 
    [switch]$nodhcp
)

#instantiate script variables
$cred = get-credential
ipconfig /flushdns
clear-host
$computers = [System.Collections.ArrayList]@()
$dhcpserver = $null
$dnsname = $null
$starttime = $(get-date -UFormat "%d-%B-%Y")
$timestamp = $(get-date -f MMddyyyy_HHmmss)
$windowHeight = (Get-Host).UI.RawUI.WindowSize.Height
$centers = @("ALB","ANT","AUG","AUR","AYA","BAC","BAG","BCR","BOS",
    "BRI","BRV","BUR","CAV","CDO","CEB","CIP","COL","CPZ",
    "DAL","DAV","EAG","EAS","EDN","EDS","ELP","FMT","FRB",
    "FTL","FVT","FVW","FWA","GIG","GSN","GUR","GUY","HOB",
    "IDR","JAM","JOP","JPR","KIL","LAO","LOU","LVS","MAH",
    "MAK","MAN","MAR","MAU","MCA","MCK","MKL","MOH","MON",
    "MUR","NIN","OAK","OCT","OGD","ORL","PAN","PAS","PDR",
    "POR","PSL","PWH","RBC","REM","REN","RIC","SAN","SDG",
    "SHR","SLV","SRV","STP","STR","SUC","TOR","TRE","VTS",
    "WAH","WBL","WSM","WVL")
$clients = @("AAC","ABB","ABI","ABT","ACO","ADI","ADO","ADS","ADV","AEO","AFP","AGA","AGI","AIQ","AIZ","AJB","ALC",
"ALP","ALS","AMT","AMX","AMZ","ANN","AOS","APL","APO","APR","ASR","ASU","ATT","AVA","AVH","AVS","AXP","B2X","BAR","BBS",
"BBY","BCB","BCM","BCS","BCO","BCP","BDO","BEL","BGT","BHC","BHN","BIC","BIS","BMG","BKG","BKT","BLC","BLG","BLH","BMW",
"BOA","BOM","BPI","BSC","BSE","BSL","BTU","BVT","BWN","BYR","BZE","CAE","CAI","CAM","CAP","CAR","CBA","CBK","CBS","CCL",
"CDS","CEN","CFX","CGO","CHS","CHT","CIT","CKM","CLA","CLE","CLR","CLV","CMP","CNH","COB","COM","CON","CCI","COX","CPA",
"CPL","CRK","CRR","CRT","CSC","CTN","CTO","CTP","CTR","CVA","CVS","CWS","CXL","CYV","DCT","DDP","DEX","DJO","DOD","DRB",
"DSG","DSH","DSY","DTL","DTO","DTV","DUB","DWI","EAR","EBH","ECH","EEG","EFX","EGE","EHI","EHT","ENR","EPI","EPS","ETR",
"ESA","EXN","EXP","EXS","FBK","FCA","FCB","FCD","FDR","FDX","FEM","FHR","FIS","FLB","FLI","FLK","FLN","FMT","FOS","FOX",
"FRC","FRN","FRW","FTD","GDD","GFS","GGL","GHB","GHP","GIB","GLB","GLO","GMC","GMY","GPF","GSK","GTC","GTG","GUT","GVB",
"HAL","HBI","HCS","HDF","HDP","HDY","HHL","HHS","HIL","HIQ","HLF","HNS","HNT","HOA","HOC","HOE","HOP","HOR","HOT","HPR",
"HRB","HRC","HRT","HSA","HUA","HUM","HYT","sure","ICM","IDE","IDR","IGM","IKA","INS","INV","IOW","ITS","JLR","JPK","JPM",
"KCH","KIW","KMS","KOL","KGN","KUR","KUS","LAV","LAZ","LBR","LBU","LCI","LFT","LIB","LIF","LPC","LTR","LTV","MAE","MAS",
"MAU","MBS","MCP","MDA","MDI","MDS","MDT","MER","MHE","MIC","MJN","MNT","MOL","MON","MSH","MTX","MXC","NAV","NCL","NER",
"NEX","NFX","NHI","NJM","NKE","NOK","NTA","NXA","NYL","NYT","NYU","OCN","OHL","ORB","OSL","PAM","PCB","PEA","PGX","PHL",
"PLD","PLI","PMI","PNG","PNI","PPH","PPJ","PPS","PRC","PRO","PRU","PSC","PTC","QND","RBB","RBH","ROB","RBK","RCB","RDG",
"REB","RFC","RKT","RNG","ROG","RSS","SAM","SAN","SBX","SCT","SDC","SEG","SFA","SFI","SGC","SGE","SGP","SGS","SHK","SHP",
"SIA","SKM","SLM","SMC","SMG","SMT","SNY","SOS","SPA","SPF","SPK","SPR","SPT","SSE","SSF","STF","STK","STM","SUN","SUP",
"SWI","SXM","SYM","TEL","TFC","TFS","TGT","TIK","TIM","TLN","TMB","TMC","TMI","TOS","TPF","TMU","TRS","TRU","TUR","TWC",
"TXU","TZL","UAA","UAM","UBR","UHC","UNC","USB","UST","UVB","VAC","VER","VFS","VGO","VID","VOD","VON","VOW","VOY","VSH",
"VST","VWG","VZW","WAG","WIN","WLC","WMT","WOP","WTP","WTR","WUN","WWG","WYN","XIA","YCA","YGC","YHO","YLE","ZAL","ZLW")
$special = @("ADM","CLT","ITD","LAP","MUL","QAS","TRN","WFM")

#utility functions
function take-screenshot
{
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    #$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $Width  = [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize.Width
    $Height = [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize.Height
    #$Left   = $Screen.Left
    $Left   = 0
    $Top    = 0
    $bitmap  = New-Object System.Drawing.Bitmap $Width, $Height
    $graphic = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)
    $bitmap.Save("$($pwd)\$($args[0])-$($starttime).jpg")
}

function Export-Png
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    Position=0)]
        [string[]]$InputObject,
        [string]$Path
    )
    begin
    {
        [Collections.Generic.List[String]]$lines = @()
    }
    Process
    {
        $null = $lines.Add($InputObject)
    }
    End
    {
 #       using namespace System.Drawing
 #       using namespace System.Windows.Forms
        Add-Type –AssemblyName System.Drawing
        Add-Type –AssemblyName System.Windows.Forms
        [string]$lines = $lines -join "`n"
        [Bitmap]$bmpImage = [Bitmap]::new(1, 1)
        [Font]$font = [Font]::new("[FontFamily]::GenericMonospace", 16, [FontStyle]::Regular, [GraphicsUnit]::Pixel)
        [Graphics]$Graphics = [Graphics]::FromImage($BmpImage)
        [int]$width  = $Graphics.MeasureString($lines, $Font).Width
        [int]$height = $Graphics.MeasureString($lines, $Font).Height
        $BmpImage = [Bitmap]::new($width, $height)
        $Graphics = [Graphics]::FromImage($BmpImage)
        #$Graphics.Clear([Color]::DarkMagenta)
        $Graphics.Clear([Color]::FromArgb(1, 36, 86))
        $Graphics.SmoothingMode = [Drawing2D.SmoothingMode]::Default
        $Graphics.TextRenderingHint = [Text.TextRenderingHint]::SystemDefault
        $Graphics.TextRenderingHint = [Text.TextRenderingHint]::ClearTypeGridFit
        $brushColour = [SolidBrush]::new([Color]::FromArgb(238, 237, 240))
        $lines
        $Graphics.DrawString($lines, $Font, $brushColour, 0, 0)
        $Graphics.Flush()
        if ($Path)
        {
            [System.IO.Directory]::SetCurrentDirectory(((Get-Location -PSProvider FileSystem).ProviderPath))
            $Path = [System.IO.Path]::GetFullPath($Path)
            $bmpImage.Save($Path, [Imaging.ImageFormat]::Png)
        }
    }
}

#Check input parameters
if (!$nodhcp -and !$filtervlan)
{
    clear-host
    write-host "You did not specify either -nodhcp or -filtervlan." -foreground yellow
    write-host "Do you want to retrieve active devices from the DHCP server?" -foreground yellow
    $temp = $null
    do { $temp = (read-host "Y or N") -as [string] } While ("Y","N" -notcontains $temp)
    clear-host
    switch ($temp) {
        "Y" { do { $filtervlan = (read-host "3 letter location ID") -as [string] } While ($centers -notcontains $filtervlan); $nodhcp = $false }
        "N" { $nodhcp = $true }
    }
    clear-host
}
if (!$filterdevice)
{
    $filterdevice = [System.Collections.ArrayList]@()
    clear-host
    write-host "You did not specify a device filter." -foreground yellow
    write-host "Please enter a valid device filter e.g. REM-LAP" -foreground yellow
    do { $filterdevice = ((read-host "filter?") -as [string]).split("-") } While (($centers -notcontains $filterdevice[0]) -or ($clients -notcontains $filterdevice[1] -and $special -notcontains $filterdevice[1]))
    $filterdevice = $filterdevice[0],$filterdevice[1] -join "-"
    clear-host
}
if (!$file)
{
    $temp = $null
    clear-host
    write-host "You did not specify a file." -foreground yellow
    if ($nodhcp -eq $false)
    {
        write-host "Would you like to import a file?" -foreground yellow
        do { $temp = (read-host "Y or N") -as [string] } While ("Y","N" -notcontains $temp)
    }
    else
    {
        $temp = "Y"    
    }
    switch ($temp) {
        "Y" { do { $file = (read-host "Enter /path/to/file.txt") -as [string] } While (!$(test-path $file)); $computers += get-content $file | sort -unique}
        "N" { break }
    }
    clear-host
}
else
{
    while (!$(test-path $file)) { $file = (read-host "File does not exist. Enter /path/to/file.txt") -as [string] }
    $computers += get-content $file | sort -unique
}
#query dhcp server for leases
if ($nodhcp -eq $false)
{
    #get dhcp server IPAddress & verify
    $dhcpserver = ((Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled=$true" | Select DHCPServer -ExpandProperty DHCPServer) -as [IPAddress]).IPAddressToString

    #use dhcp server IP to filter your dhcp server from list of dhcp servers in domain, set var, verify
    $dnsname = Get-DhcpServerInDC -ErrorAction stop | where-object {$_.IPAddress -like "$dhcpserver"} | select DnsName -ExpandProperty DnsName

    #get vlans->filter by state and location->get all active leases for each returned vlan->filter by device name prefix you entered earlier->split results to get hostname and drop domain name.
    $computers += Get-DhcpServerv4Scope -ComputerName $dnsname -ErrorAction stop | Where-Object {$_.Name -like "$($filtervlan)*" -and $_.State -eq "Active"} | Get-DhcpServerv4Lease -ComputerName $dnsname -ErrorAction stop | Where-Object {($_.AddressState -eq "Active" -or $_.AddressState -eq "ActiveReservation") -and $_.Hostname -like "$($filterdevice)*"} | select-object -Property HostName -ExpandProperty HostName | foreach-object { $_.Split(".")[0] } 
}
#sort list, and update device text file
$computers = ($computers | sort -unique).ToUpper()
if ($file -ne $null)
{
    clear-content $file
    $computers | out-file $file
}
Write-Host (Get-Date) -ForegroundColor Yellow
write-host "Sending $($computers.count) jobs" -foreground yellow
$JobTimeOut = 3600
$ScriptBlock = { manage-bde -status | select -first 50 }
$Session = New-PSSession -ComputerName $computers -Credential $cred -ErrorAction SilentlyContinue -ErrorVariable err
$job = Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -ThrottleLimit 50 -AsJob -ErrorAction SilentlyContinue
$jobs = $job | Get-Job -IncludeChildJob
Write-Host ("Waiting up to " + (($JobTimeOut / 60).ToString("0.0") ) + " minutes for job to complete") -ForegroundColor Yellow
$null = $jobs | Wait-Job -Timeout $JobTimeOut
$ReturnValues = $jobs | Receive-Job -ErrorAction SilentlyContinue
clear-host
#create dir and files
New-Item -Path "$($pwd)" -Name "scan-$($timestamp)" -ItemType "directory"
clear-host
$scandir = "\scan-$($timestamp)"
set-location $pwd$scandir

$null > results$($starttime).txt
$null > results$($starttime).csv
#$null > errors$($starttime).txt
$null > MISSING$($starttime).txt
$startcount = 0
$returnedcomputers = $ReturnValues | select -Property PSComputerName -unique -ExpandProperty PSComputerName
$computers | where {$returnedcomputers -notcontains $_} | add-content MISSING$($starttime).txt
$finishcount = $returnedcomputers.count
foreach ($x in $returnedcomputers)
{
    clear-host
    $startcount++
    $encryptionmethod = $null
    write-host "Result $($startcount)/$($finishcount)"
    $temp = "Computer Name: $($x)" | out-string | tee-object -filepath results$($starttime).txt -append
#    write-host "Computer Name: $($x)" | tee-object -filepath results$($starttime).txt -append
#    $ReturnValues | where-object {$_.PSComputerName -eq $x} | tee-object -filepath results$($starttime).txt --append
    $temp += $ReturnValues | where-object {$_.PSComputerName -eq $x} | out-string | tee-object -filepath results$($starttime).txt -append
    start-sleep -seconds 1
#    take-screenshot($x)
    $temp | out-string | Export-Png -path "$($pwd)\$($x)-$($starttime).png"
    start-sleep -seconds 1
    clear-host
#    "Computer Name: $($x)" | add-content results$($starttime).txt
#    $ReturnValues | where-object {$_.PSComputerName -eq $x} | add-content results$($starttime).txt
    $encryptionmethod = ($ReturnValues | where-object {$_.PSComputerName -eq $x} | select-string 'Encryption Method'| foreach-object {"$_".split(":")[1]}).trim()
    "$($x),$($encryptionmethod),$($starttime)" | add-content results$($starttime).csv
}
write-host "Script Complete!" -foreground yellow
write-host "Bitlocker Results: $($pwd)\results$($starttime).txt" -foreground yellow
write-host "Excel results: $($pwd)\results$($starttime).csv" -foreground yellow
if ($finidhcount -lt $computers.count)
{
    write-host "Missing" $([int]$computers.count - [int]$finishcount) "devices: $($pwd)\MISSING$($starttime).txt" -foreground yellow
}
set-location ..
exit