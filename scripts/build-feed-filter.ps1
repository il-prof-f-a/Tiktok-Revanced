[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputApk,
    [string]$JavaHome = $env:JAVA_HOME,
    [string]$OutputRoot = (Join-Path $env:LOCALAPPDATA 'FeedConCura/build-output')
)

$ErrorActionPreference = 'Stop'
$inputPath = (Resolve-Path -LiteralPath $InputApk).Path
if ([IO.Path]::GetExtension($inputPath) -ne '.apk') { throw 'Input must be an APK.' }
if (!$JavaHome) { throw 'Set JAVA_HOME or pass -JavaHome with a full JDK 21.' }
$java = Join-Path $JavaHome 'bin/java.exe'
$keytool = Join-Path $JavaHome 'bin/keytool.exe'
if (!(Test-Path $java) -or !(Test-Path $keytool)) { throw 'Full JDK required.' }
$toolsRoot = Join-Path $env:LOCALAPPDATA 'FeedConCura/build-tools'
New-Item -ItemType Directory -Force $toolsRoot | Out-Null

function Get-VerifiedTool($Name, $Url, $Sha256) {
    $path = Join-Path $toolsRoot $Name
    if (!(Test-Path -LiteralPath $path)) { Invoke-WebRequest -Uri $Url -OutFile $path }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Sha256) {
        throw "Checksum mismatch: $Name"
    }
    return $path
}

$cli = Get-VerifiedTool 'morphe-desktop-1.19.1-all.jar' `
    'https://github.com/MorpheApp/morphe-desktop/releases/download/v1.19.1/morphe-desktop-1.19.1-all.jar' `
    'a51472252cd63b2eac635dbb5a154ff918bfc15268da89679feb3d760230c573'
$bundle = Get-VerifiedTool 'patches-0.8.1.mpp' `
    'https://github.com/icysymmetra/tiktok-patches-for-morphe/releases/download/v0.8.1/patches-0.8.1.mpp' `
    'ae38a19c7eecad07622e4873db3a44a780bc12ba417ac6fbfabbdfea03e69c0f'

$runPath = Join-Path $OutputRoot ([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory $runPath -Force | Out-Null
$keystore = Join-Path $runPath 'local-test.p12'
$output = Join-Path $runPath 'tiktok-feed-filter-test.apk'
$report = Join-Path $runPath 'patch-result.json'
# A fresh local test identity per run; never reuse the upstream signing key.
$env:FEEDCONCURA_BUILD_KEY_PASSWORD = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
try {
    & $keytool -genkeypair -keystore $keystore -storetype PKCS12 -alias feedconcura-test `
        -storepass:env FEEDCONCURA_BUILD_KEY_PASSWORD -keyalg RSA -keysize 2048 `
        -validity 365 -dname 'CN=FeedConCura local test' -noprompt
    if ($LASTEXITCODE -ne 0) { throw 'Test key generation failed.' }
    # Settings is the configuration UI for the feed filter. All other optional patches stay excluded.
    & $java -Xmx6g -jar $cli patch $inputPath -p $bundle --exclusive `
        -e 'Feed filter' -e 'Settings' -o $output -r $report `
        -t (Join-Path $runPath 'scratch') --keystore $keystore `
        --keystore-entry-alias feedconcura-test `
        --keystore-password $env:FEEDCONCURA_BUILD_KEY_PASSWORD `
        --keystore-entry-password $env:FEEDCONCURA_BUILD_KEY_PASSWORD `
        --signer 'FeedConCura local test' 2>&1 | Tee-Object -FilePath (Join-Path $runPath 'build.log')
    if ($LASTEXITCODE -ne 0) { throw "Patching failed. See $runPath" }
    if (!(Test-Path -LiteralPath $output)) { throw 'No output APK generated.' }
    $manifest = [ordered]@{
        inputSha256 = (Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash
        outputSha256 = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
        cliVersion = '1.19.1'; patchesVersion = '0.8.1'
        selectedPatches = @('Feed filter', 'Settings')
        signature = 'Fresh local test key; not an upstream or production identity'
        runtimeTested = $false
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $runPath 'build-manifest.json') -Encoding utf8
    Write-Output "APK: $output"
} finally {
    Remove-Item Env:FEEDCONCURA_BUILD_KEY_PASSWORD -ErrorAction SilentlyContinue
}
