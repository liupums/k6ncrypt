# Create the chain of trust certs
# The core cmdlet is New-SelfSignedCertificate
# https://docs.microsoft.com/en-us/powershell/module/pkiclient/new-selfsignedcertificate?view=win10-ps
# The extensions
# 1. basic contrains extension
# https://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509basicconstraintsextension(v=vs.110).aspx
#    bool certificateAuthority
#    bool hasPathLengthConstraint
#    int pathLengthConstraint
#    bool critical
# 2. Enhanced Key Usage
# https://docs.microsoft.com/en-us/powershell/module/pkiclient/new-selfsignedcertificate?view=win10-ps
#    Client Authentication. 1.3.6.1.5.5.7.3.2
#    Server Authentication. 1.3.6.1.5.5.7.3.1
#    Enhanced Key Usage. 2.5.29.37
#    By default, Enhanced Key Usage will include both Client and Server Authentication.

param (   
    [Parameter(Mandatory=$true)][string]$action
)

# Return ThumbPrint for a given cert file
function GetThumbPrint($filePath)
{
    $cert=(new-object -typename  "System.Security.Cryptography.X509Certificates.X509Certificate2") 
    $cert.import("$filePath") 
    write $cert.ThumbPrint
}

# Remove a cert from Cert:\ recursively for the given ThumbPrint
function RemoveCertFromStore([string]$thumbprint)
{
    Get-ChildItem -path cert:\ -Recurse | where-object { $_.thumbprint -eq $thumbprint } | Remove-Item -ErrorAction SilentlyContinue    
}

#create End leaf cert stored in "cert:\LocalMachine\My"
function createLeafCert([object]$signingCert, [string]$CN)
{
    # SAN is defined in -DnsName
    $selfSignedArgs =@{"-Subject"="CN=$CN";
                    "-DnsName"="$CN";
                    "-CertStoreLocation"="cert:\LocalMachine\My";
                    "-NotAfter"=(get-date).AddDays(30); 
                    }

    # Add signer
    $selfSignedArgs += @{"-Signer"=$signingCert }

    $basicConstrains = new-object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension $false,$false,0,$true
    $caPem =  @(
            '-----BEGIN CERTIFICATE-----'
            [System.Convert]::ToBase64String($signingCert.RawData, 'InsertLineBreaks')
            '-----END CERTIFICATE-----'
        )

    # Add Embedded Ca Cert 1.2.840.113556.1.8000.2554.197254.100
    $caPemStr = $caPem -join ""
    $caPemBytes = [system.Text.Encoding]::ASCII.GetBytes($caPemStr)
    $embeddedCA = new-object System.Security.Cryptography.X509Certificates.X509Extension "1.2.840.113556.1.8000.2554.197254.100",$caPemBytes,$false
    $selfSignedArgs += @{"-Extension"=@($basicConstrains, $embeddedCA) }

    # Add Server Authentication 1.3.6.1.5.5.7.3.1 
    # Add Client Authentication 1.3.6.1.5.5.7.3.2
    $selfSignedArgs += @{"-TextExtension"=@("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2")}

    $keyUsages=@("DigitalSignature","DataEncipherment","KeyEncipherment")
    $selfSignedArgs += @{"-KeyUsage"=$keyUsages }

    write (New-SelfSignedCertificate @selfSignedArgs)
}


# Create CA cert, stored in "cert:\LocalMachine\My"
function CreateCACert([object]$signingCert, [string]$CN)
{
    $selfSignedArgs =@{"-Subject"="CN=$CN";
                    "-CertStoreLocation"="cert:\LocalMachine\My";
                    "-NotAfter"=(get-date).AddDays(30); 
                    }

    $selfSignedArgs += @{"-Signer"=$signingCert }
    $basicConstrains = new-object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension $true,$false,0,$true
    $selfSignedArgs += @{"-Extension"=@($basicConstrains) }

    $keyUsages=@("CertSign","CRLSign")
    $selfSignedArgs += @{"-KeyUsage"=$keyUsages }
    write (New-SelfSignedCertificate @selfSignedArgs)
}

# Create root CA cert, stored in "cert:\LocalMachine\My"
function CreateRootCert([string]$CN)
{
    #no signer for root, it is self-signed
    $selfSignedArgs =@{"-Subject"="CN=$CN";
                    "-CertStoreLocation"="cert:\LocalMachine\My";
                    "-NotAfter"=(get-date).AddDays(30); 
                    }
    $basicConstrains = new-object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension $true,$false,0,$true
    $selfSignedArgs += @{"-Extension"=@($basicConstrains) }

    $keyUsages=@("CertSign","CRLSign")
    $selfSignedArgs += @{"-KeyUsage"=$keyUsages }

    # return the new root cert 
    write (New-SelfSignedCertificate @selfSignedArgs)
}

# Set up cert store
# 1. in cert store cert:/LocalMachine/My
#    a. Leaf server cert with private key
#    b. Leaf client cert with private key
# 2. in the file system
#    a. public Root cert (removed from cert store)
#    b. public CA cert (removed from cert store)
function MyCreate()
{
  $rootCert = CreateRootCert -CN $FAKEROOT
  $caCert = CreateCACert -signingCert $rootCert -CN $FAKECA
  $servLeafCert = createLeafCert -signingCert $caCert -CN $FAKESERVER
  $clientLeafCert = createLeafCert -signingCert $caCert -CN $FAKECLIENT

  Write-host "Save client leaf chained PEM to file system: client leaf, ca, root"  
  $cPem=new-object System.Text.StringBuilder
  [void]$cPem.AppendLine("-----BEGIN CERTIFICATE-----")
  [void]$cPem.AppendLine([System.Convert]::ToBase64String($clientLeafCert.RawData,'InsertLineBreaks'))
  [void]$cPem.AppendLine("-----END CERTIFICATE-----")
  [void]$cPem.AppendLine("-----BEGIN CERTIFICATE-----")
  [void]$cPem.AppendLine([System.Convert]::ToBase64String($caCert.RawData,'InsertLineBreaks'))
  [void]$cPem.AppendLine("-----END CERTIFICATE-----")
  [void]$cPem.AppendLine("-----BEGIN CERTIFICATE-----")
  [void]$cPem.AppendLine([System.Convert]::ToBase64String($rootCert.RawData,'InsertLineBreaks'))
  [void]$cPem.AppendLine("-----END CERTIFICATE-----")
  $cPem.ToString() | out-file "$path\$FAKECLIENT.pem"
  $clientLeafCertThumbprint = $clientLeafCert.ThumbPrint
  "engine:e_ncrypt:machine:my:$clientLeafCertThumbprint" | out-file "$path\$FAKECLIENT.keyid"


  Write-host "Save server leaf chained PEM to file system: client leaf, ca, root"  
  $sPem=new-object System.Text.StringBuilder
  [void]$sPem.AppendLine("-----BEGIN CERTIFICATE-----")
  [void]$sPem.AppendLine([System.Convert]::ToBase64String($servLeafCert.RawData,'InsertLineBreaks'))
  [void]$sPem.AppendLine("-----END CERTIFICATE-----")
  [void]$sPem.AppendLine("-----BEGIN CERTIFICATE-----")
  [void]$sPem.AppendLine([System.Convert]::ToBase64String($caCert.RawData,'InsertLineBreaks'))
  [void]$sPem.AppendLine("-----END CERTIFICATE-----")
  [void]$sPem.AppendLine("-----BEGIN CERTIFICATE-----")
  [void]$sPem.AppendLine([System.Convert]::ToBase64String($rootCert.RawData,'InsertLineBreaks'))
  [void]$sPem.AppendLine("-----END CERTIFICATE-----")
  $sPem.ToString() | out-file "$path\$FAKESERVER.pem"
  $serverLeafCertThumbprint = $servLeafCert.ThumbPrint
  "engine:e_ncrypt:machine:my:$serverLeafCertThumbprint" | out-file "$path\$FAKESERVER.keyid"

  Write-host "Save root PEM to file system"  
  $rPem=new-object System.Text.StringBuilder
  [void]$rPem.AppendLine("-----BEGIN CERTIFICATE-----")
  [void]$rPem.AppendLine([System.Convert]::ToBase64String($rootCert.RawData,'InsertLineBreaks'))
  [void]$rPem.AppendLine("-----END CERTIFICATE-----")
  $rPem.ToString() | out-file "$path\$FAKEROOT.pem"

  Export-Certificate -Cert $rootCert -FilePath "$path\$FAKEROOT.cer"  | Out-Null
  Export-Certificate -Cert $caCert -FilePath "$path\$FAKECA.cer"  | Out-Null
  
  Write-host "Remove fake ROOT cert from cert store."  
  RemoveCertFromStore($rootCert.ThumbPrint)

  Write-host "Remove fake CA cert from cert store."  
  RemoveCertFromStore($caCert.ThumbPrint)
}

# Clean up cert store created by MyCreate() and restore to previous state
function MyCleanUp()
{
  Write-host "Remove leaf server and client cert from cert store."  
  Get-Childitem -path cert:\  -Recurse | Where-Object { $_.issuer -like "CN=$FAKECA" }  | remove-item -ErrorAction SilentlyContinue | Out-Null

  if ([System.IO.File]::Exists("$path\$FAKEROOT.cer"))
  {
     Write-host "Remove fake ROOT cert from cert store."  
     RemoveCertFromStore(GetThumbPrint("$path\$FAKEROOT.cer"))
     Write-host "Remove fake ROOT cert from file system."  
     [System.IO.File]::Delete("$path\$FAKEROOT.cer")
  }

  if ([System.IO.File]::Exists("$path\$FAKECA.cer"))
  {
     Write-host "Remove fake CA cert from cert store."  
     RemoveCertFromStore(GetThumbPrint("$path\$FAKECA.cer"))
     Write-host "Remove fake CA cert from file system."  
     [System.IO.File]::Delete("$path\$FAKECA.cer")
  }

  if ([System.IO.File]::Exists("$path\$FAKEROOT.pem"))
  {
     Write-host "Remove fake ROOT pem from file system."  
     [System.IO.File]::Delete("$path\$FAKEROOT.pem")
  }

  if ([System.IO.File]::Exists("$path\$FAKESERVER.pem"))
  {
     Write-host "Remove fake server pem from file system."  
     [System.IO.File]::Delete("$path\$FAKESERVER.pem")
  }

  if ([System.IO.File]::Exists("$path\$FAKESERVER.keyid"))
  {
     Write-host "Remove fake server keyid from file system."  
     [System.IO.File]::Delete("$path\$FAKESERVER.keyid")
  }

  if ([System.IO.File]::Exists("$path\$FAKECLIENT.pem"))
  {
     Write-host "Remove fake client pem from file system."  
     [System.IO.File]::Delete("$path\$FAKECLIENT.pem")
  }

  if ([System.IO.File]::Exists("$path\$FAKECLIENT.keyid"))
  {
     Write-host "Remove fake client keyid from file system."  
     [System.IO.File]::Delete("$path\$FAKECLIENT.keyid")
  }
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))
{
    Write-host "please run CreateChainCerts.ps1 as ADMIN."  
    return
}

$path=pwd
$FAKEROOT="FakeRoot"
$FAKECA="FakeCA"
$FAKESERVER="FakeServer"
$FAKECLIENT="FakeClient"

if ($action -eq "create")
{
    MyCreate
    return
}

if ($action -eq "clean")
{
    MyCleanUp
    return
}

Write-host "Usage: CreateChainCerts.ps1 <create|clean>"
