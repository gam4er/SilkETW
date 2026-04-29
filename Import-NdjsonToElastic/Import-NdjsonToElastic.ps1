<#
.SYNOPSIS
Streams an NDJSON file into a local Elasticsearch index for ad-hoc search.

.DESCRIPTION
This is a pragmatic helper script for large NDJSON files. It validates the input,
normalizes text encoding to UTF-8 when needed, uses jq to turn NDJSON into an
Elasticsearch bulk stream, creates a search-friendly index, and uploads the data
in batches without loading the whole file into memory.

It is intended for local Docker Elasticsearch usage, not for hardened production
ingestion.

.EXAMPLE
./Import-NdjsonToElastic.ps1 -NdjsonPath .\object_BlueHammer.ndjson -IndexName bluehammer -Recreate

.EXAMPLE
./Import-NdjsonToElastic.ps1 .\object_BlueHammer.ndjson bluehammer -DocsPerBulk 2000 -KeepChunks

.EXAMPLE
./Import-NdjsonToElastic.ps1 .\object_BlueHammer.ndjson bluehammer -DataViewPattern 'bluehammer*'

.NOTES
Requires PowerShell 7+ and jq in PATH. Creates or updates a Kibana Data View by default.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias('Path')]
    [ValidateNotNullOrEmpty()]
    [string]$NdjsonPath,

    [Parameter(Mandatory = $true, Position = 1)]
    [Alias('Index')]
    [ValidateNotNullOrEmpty()]
    [string]$IndexName,

    [ValidateNotNullOrEmpty()]
    [string]$ElasticUrl = 'http://localhost:9200',

    [ValidateNotNullOrEmpty()]
    [string]$KibanaUrl = 'http://localhost:5601',

    [ValidateNotNullOrEmpty()]
    [string]$ElasticUser = 'elastic',

    [Alias('Password')]
    [AllowNull()]
    [System.Security.SecureString]$ElasticPassword,

    [ValidateRange(1, [int]::MaxValue)]
    [int]$DocsPerBulk = 5000,

    [ValidateRange(1, 1440)]
    [int]$HttpTimeoutMinutes = 30,

    # Kibana Data View pattern. Defaults to the exact index name.
    [string]$DataViewPattern = '',

    # Optional display name for the Kibana Data View. Defaults to the pattern.
    [string]$DataViewName = '',

    # If set, skip Kibana Data View creation/update after import.
    [switch]$SkipDataViewCreation,

    # If set, existing index will be deleted before import.
    [switch]$Recreate,

    # Keep generated bulk chunks on disk. Useful for debugging failed batches.
    [switch]$KeepChunks,

    # Working directory for generated mapping, jq filter, chunks and error files.
    [string]$WorkDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Runtime = $null

function Assert-PowerShell7OrLater {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'Run this script in PowerShell 7 or later (pwsh). The script relies on ProcessStartInfo.ArgumentList and output encoding support.'
    }
}

function Resolve-RequiredCommand {
    param([Parameter(Mandatory = $true)][string[]]$CandidateNames)

    foreach ($candidateName in $CandidateNames) {
        $command = Get-Command $candidateName -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command
        }
    }

    throw "Required command was not found in PATH. Install one of: $($CandidateNames -join ', ')"
}

function Resolve-InputFilePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $resolvedPath = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        throw "NDJSON file '$Path' was not found."
    }

    $item = Get-Item -LiteralPath $resolvedPath.Path -ErrorAction Stop
    if ($item.PSIsContainer) {
        throw "NDJSON path '$Path' points to a directory. Provide a file path instead."
    }

    return $item.FullName
}

function ConvertTo-SafeIndexNameCheck {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($Name -cne $Name.ToLowerInvariant()) {
        throw "Elasticsearch index name must be lowercase. Provided: '$Name'"
    }

    if ($Name -match '[\\/\*\?"<>\| ,#:]') {
        throw "Elasticsearch index name contains an invalid character. Provided: '$Name'"
    }

    if ($Name.StartsWith('-') -or $Name.StartsWith('_') -or $Name.StartsWith('+')) {
        throw "Elasticsearch index name must not start with '-', '_' or '+'. Provided: '$Name'"
    }

    if ($Name -in @('.', '..')) {
        throw "Elasticsearch index name must not be '.' or '..'. Provided: '$Name'"
    }

    if ($Name.Length -gt 255) {
        throw "Elasticsearch index name must be 255 characters or shorter. Provided length: $($Name.Length)"
    }
}

function Get-PlainTextFromSecureString {
    param([Parameter(Mandatory = $true)][System.Security.SecureString]$Value)

    return [System.Net.NetworkCredential]::new('', $Value).Password
}

function Get-EffectiveElasticPassword {
    param([AllowNull()][System.Security.SecureString]$Password)

    if ($null -ne $Password) {
        return (Get-PlainTextFromSecureString -Value $Password)
    }

    if (-not [string]::IsNullOrWhiteSpace($env:ELASTIC_PASSWORD)) {
        return $env:ELASTIC_PASSWORD
    }

    return 'changeme'
}

function Get-NormalizedElasticUrl {
    param([Parameter(Mandatory = $true)][string]$Url)

    [System.Uri]$uri = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)) {
        throw "ElasticUrl must be an absolute http/https URL. Provided: '$Url'"
    }

    if ($uri.Scheme -notin @('http', 'https')) {
        throw "ElasticUrl must start with http:// or https://. Provided: '$Url'"
    }

    return $uri.AbsoluteUri.TrimEnd('/')
}

function Get-NormalizedKibanaUrl {
    param([Parameter(Mandatory = $true)][string]$Url)

    return (Get-NormalizedElasticUrl -Url $Url)
}

function Get-EffectiveDataViewPattern {
    param(
        [string]$Pattern,
        [Parameter(Mandatory = $true)][string]$IndexName
    )

    if ([string]::IsNullOrWhiteSpace($Pattern)) {
        return $IndexName
    }

    return $Pattern.Trim()
}

function Get-EffectiveDataViewName {
    param(
        [string]$Name,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $Pattern
    }

    return $Name.Trim()
}

function New-HttpClientResources {
    param([Parameter(Mandatory = $true)][int]$TimeoutMinutes)

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate

    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromMinutes($TimeoutMinutes)

    return [pscustomobject]@{
        Handler = $handler
        Client  = $client
    }
}

function Get-BasicAuthHeader {
    param(
        [Parameter(Mandatory = $true)][string]$User,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $authBytes = [System.Text.Encoding]::ASCII.GetBytes(('{0}:{1}' -f $User, $Password))
    return [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Basic', [Convert]::ToBase64String($authBytes))
}

function ConvertTo-SizeString {
    param([Parameter(Mandatory = $true)][long]$Bytes)

    $units = @('B', 'KiB', 'MiB', 'GiB', 'TiB')
    [double]$size = $Bytes
    $unitIndex = 0

    while ($size -ge 1024 -and $unitIndex -lt ($units.Count - 1)) {
        $size = $size / 1024
        $unitIndex++
    }

    return ('{0:N2} {1}' -f $size, $units[$unitIndex])
}

function ConvertTo-DurationString {
    param([Parameter(Mandatory = $true)][TimeSpan]$Duration)

    if ($Duration.TotalHours -ge 1) {
        return ('{0:hh\:mm\:ss}' -f $Duration)
    }

    return ('{0:mm\:ss}' -f $Duration)
}

function Get-ContentTypeWithUtf8 {
    param([string]$ContentType)

    if ([string]::IsNullOrWhiteSpace($ContentType)) {
        return $ContentType
    }

    if ($ContentType -match '(?i)\bcharset\s*=') {
        return $ContentType
    }

    return "$ContentType; charset=utf-8"
}

function Get-TrimmedSingleLine {
    param(
        [AllowNull()][string]$Text,
        [int]$MaxLength = 400
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $singleLine = ($Text -replace '\s+', ' ').Trim()
    if ($singleLine.Length -le $MaxLength) {
        return $singleLine
    }

    return $singleLine.Substring(0, $MaxLength) + '...'
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fffK')
    $line = '[{0}] [{1}] {2}' -f $timestamp, $Level, $Message

    if ($null -ne $script:Runtime -and -not [string]::IsNullOrWhiteSpace($script:Runtime.LogPath)) {
        [System.IO.File]::AppendAllText($script:Runtime.LogPath, $line + [System.Environment]::NewLine, $script:Runtime.Utf8NoBom)
    }

    Write-Host $line
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    [System.IO.File]::WriteAllText($Path, $Content, $script:Runtime.Utf8NoBom)
}

function Test-FileCanBeReadWithEncoding {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Text.Encoding]$Encoding
    )

    $fileStream = $null
    $reader = $null

    try {
        $fileStream = [System.IO.File]::OpenRead($Path)
        $reader = [System.IO.StreamReader]::new($fileStream, $Encoding, $true, 1024 * 1024)
        $buffer = [char[]]::new(1024 * 1024)

        while (($reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
        }

        return $true
    }
    catch [System.Text.DecoderFallbackException] {
        return $false
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
        elseif ($null -ne $fileStream) {
            $fileStream.Dispose()
        }
    }
}

function Get-TextEncodingInfo {
    param([Parameter(Mandatory = $true)][string]$Path)

    $prefix = @()
    $fileStream = $null

    try {
        $fileStream = [System.IO.File]::OpenRead($Path)
        $prefixLength = [int][Math]::Min($fileStream.Length, 4L)
        if ($prefixLength -gt 0) {
            $prefix = [byte[]]::new($prefixLength)
            [void]$fileStream.Read($prefix, 0, $prefixLength)
        }
    }
    finally {
        if ($null -ne $fileStream) {
            $fileStream.Dispose()
        }
    }

    if ($prefix.Length -ge 3 -and $prefix[0] -eq 0xEF -and $prefix[1] -eq 0xBB -and $prefix[2] -eq 0xBF) {
        return [pscustomobject]@{
            Name                = 'utf-8-bom'
            Encoding            = [System.Text.UTF8Encoding]::new($true, $true)
            HasBom              = $true
            NormalizeToUtf8NoBom = $true
        }
    }

    if ($prefix.Length -ge 4 -and $prefix[0] -eq 0xFF -and $prefix[1] -eq 0xFE -and $prefix[2] -eq 0x00 -and $prefix[3] -eq 0x00) {
        return [pscustomobject]@{
            Name                = 'utf-32-le-bom'
            Encoding            = [System.Text.UTF32Encoding]::new($false, $true)
            HasBom              = $true
            NormalizeToUtf8NoBom = $true
        }
    }

    if ($prefix.Length -ge 4 -and $prefix[0] -eq 0x00 -and $prefix[1] -eq 0x00 -and $prefix[2] -eq 0xFE -and $prefix[3] -eq 0xFF) {
        return [pscustomobject]@{
            Name                = 'utf-32-be-bom'
            Encoding            = [System.Text.UTF32Encoding]::new($true, $true)
            HasBom              = $true
            NormalizeToUtf8NoBom = $true
        }
    }

    if ($prefix.Length -ge 2 -and $prefix[0] -eq 0xFF -and $prefix[1] -eq 0xFE) {
        return [pscustomobject]@{
            Name                = 'utf-16-le-bom'
            Encoding            = [System.Text.Encoding]::Unicode
            HasBom              = $true
            NormalizeToUtf8NoBom = $true
        }
    }

    if ($prefix.Length -ge 2 -and $prefix[0] -eq 0xFE -and $prefix[1] -eq 0xFF) {
        return [pscustomobject]@{
            Name                = 'utf-16-be-bom'
            Encoding            = [System.Text.Encoding]::BigEndianUnicode
            HasBom              = $true
            NormalizeToUtf8NoBom = $true
        }
    }

    if (Test-FileCanBeReadWithEncoding -Path $Path -Encoding $script:Runtime.Utf8Strict) {
        return [pscustomobject]@{
            Name                = 'utf-8'
            Encoding            = $script:Runtime.Utf8Strict
            HasBom              = $false
            NormalizeToUtf8NoBom = $false
        }
    }

    $sampleLength = [int][Math]::Min((Get-Item -LiteralPath $Path).Length, 4096L)
    $sample = @()
    $sampleStream = $null

    try {
        $sampleStream = [System.IO.File]::OpenRead($Path)
        if ($sampleLength -gt 0) {
            $sample = [byte[]]::new($sampleLength)
            [void]$sampleStream.Read($sample, 0, $sampleLength)
        }
    }
    finally {
        if ($null -ne $sampleStream) {
            $sampleStream.Dispose()
        }
    }

    $zeroEven = 0
    $zeroOdd = 0

    for ($index = 0; $index -lt $sample.Length; $index++) {
        if ($sample[$index] -eq 0x00) {
            if (($index % 2) -eq 0) {
                $zeroEven++
            }
            else {
                $zeroOdd++
            }
        }
    }

    $minZeroCount = [Math]::Max([int]($sample.Length / 4), 1)
    $maxOppositeZeroCount = [Math]::Max([int]($sample.Length / 32), 1)

    if ($sample.Length -ge 8 -and $zeroOdd -ge $minZeroCount -and $zeroEven -le $maxOppositeZeroCount) {
        return [pscustomobject]@{
            Name                = 'utf-16-le-no-bom'
            Encoding            = [System.Text.UnicodeEncoding]::new($false, $false, $true)
            HasBom              = $false
            NormalizeToUtf8NoBom = $true
        }
    }

    if ($sample.Length -ge 8 -and $zeroEven -ge $minZeroCount -and $zeroOdd -le $maxOppositeZeroCount) {
        return [pscustomobject]@{
            Name                = 'utf-16-be-no-bom'
            Encoding            = [System.Text.UnicodeEncoding]::new($true, $false, $true)
            HasBom              = $false
            NormalizeToUtf8NoBom = $true
        }
    }

    throw "Input file '$Path' is not valid UTF-8 and has no supported BOM. Normalize it to UTF-8 before import."
}

function Convert-TextFileToUtf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][System.Text.Encoding]$SourceEncoding
    )

    $reader = $null
    $writer = $null

    try {
        $reader = [System.IO.StreamReader]::new($SourcePath, $SourceEncoding, $true, 1024 * 1024)
        $writer = [System.IO.StreamWriter]::new($DestinationPath, $false, $script:Runtime.Utf8NoBom, 1024 * 1024)
        $buffer = [char[]]::new(1024 * 1024)

        while (($charsRead = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $writer.Write($buffer, 0, $charsRead)
        }
    }
    finally {
        if ($null -ne $writer) {
            $writer.Dispose()
        }

        if ($null -ne $reader) {
            $reader.Dispose()
        }
    }
}

function Resolve-NdjsonImportSource {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$WorkDirectory
    )

    $encodingInfo = Get-TextEncodingInfo -Path $Path
    $importPath = $Path

    if ($encodingInfo.NormalizeToUtf8NoBom) {
        $importPath = Join-Path $WorkDirectory 'input.normalized.utf8.ndjson'
        Convert-TextFileToUtf8NoBom -SourcePath $Path -DestinationPath $importPath -SourceEncoding $encodingInfo.Encoding

        if (-not (Test-FileCanBeReadWithEncoding -Path $importPath -Encoding $script:Runtime.Utf8Strict)) {
            throw "Normalized UTF-8 file '$importPath' could not be validated after conversion."
        }
    }

    return [pscustomobject]@{
        OriginalPath      = $Path
        ImportPath        = $importPath
        DetectedEncoding  = $encodingInfo.Name
        HasBom            = $encodingInfo.HasBom
        WasNormalized     = $encodingInfo.NormalizeToUtf8NoBom
    }
}

function Initialize-ImportRuntime {
    param(
        [Parameter(Mandatory = $true)][string]$NdjsonPathValue,
        [Parameter(Mandatory = $true)][string]$IndexNameValue,
        [Parameter(Mandatory = $true)][string]$ElasticUrlValue,
        [Parameter(Mandatory = $true)][string]$KibanaUrlValue,
        [Parameter(Mandatory = $true)][string]$ElasticUserValue,
        [AllowNull()][System.Security.SecureString]$ElasticPasswordValue,
        [Parameter(Mandatory = $true)][int]$DocsPerBulkValue,
        [Parameter(Mandatory = $true)][int]$HttpTimeoutMinutesValue,
        [string]$DataViewPatternValue,
        [string]$DataViewNameValue,
        [switch]$SkipDataViewCreationValue,
        [string]$WorkDirValue
    )

    Assert-PowerShell7OrLater
    ConvertTo-SafeIndexNameCheck -Name $IndexNameValue

    $ndjsonPathFull = Resolve-InputFilePath -Path $NdjsonPathValue
    $elasticUrlNorm = Get-NormalizedElasticUrl -Url $ElasticUrlValue
    $kibanaUrlNorm = ''
    $effectivePassword = Get-EffectiveElasticPassword -Password $ElasticPasswordValue
    $jqCommand = Resolve-RequiredCommand -CandidateNames @('jq.exe', 'jq')
    $httpResources = New-HttpClientResources -TimeoutMinutes $HttpTimeoutMinutesValue
    $effectiveDataViewPattern = ''
    $effectiveDataViewName = ''

    if (-not $SkipDataViewCreationValue) {
        $kibanaUrlNorm = Get-NormalizedKibanaUrl -Url $KibanaUrlValue
        $effectiveDataViewPattern = Get-EffectiveDataViewPattern -Pattern $DataViewPatternValue -IndexName $IndexNameValue
        $effectiveDataViewName = Get-EffectiveDataViewName -Name $DataViewNameValue -Pattern $effectiveDataViewPattern
    }

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $utf8Strict = [System.Text.UTF8Encoding]::new($false, $true)

    $resolvedWorkDir = $WorkDirValue
    if ([string]::IsNullOrWhiteSpace($resolvedWorkDir)) {
        $resolvedWorkDir = Join-Path (Split-Path -Parent $ndjsonPathFull) ('_bulk_import_{0}_{1}' -f $IndexNameValue, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    }

    $workDirFull = [System.IO.Path]::GetFullPath($resolvedWorkDir)
    New-Item -ItemType Directory -Force -Path $workDirFull | Out-Null

    $ndjsonFile = Get-Item -LiteralPath $ndjsonPathFull -ErrorAction Stop

    $script:Runtime = [pscustomobject]@{
        IndexName           = $IndexNameValue
        NdjsonPathFull      = $ndjsonPathFull
        NdjsonFileSizeBytes = $ndjsonFile.Length
        ElasticUrlNorm      = $elasticUrlNorm
        KibanaUrlNorm       = $kibanaUrlNorm
        KibanaApiRoot       = if ([string]::IsNullOrWhiteSpace($kibanaUrlNorm)) { '' } else { "$kibanaUrlNorm/api" }
        ElasticUser         = $ElasticUserValue
        DocsPerBulk         = $DocsPerBulkValue
        HttpTimeoutMinutes  = $HttpTimeoutMinutesValue
        SkipDataViewCreation = [bool]$SkipDataViewCreationValue
        DataViewPattern     = $effectiveDataViewPattern
        DataViewName        = $effectiveDataViewName
        DataViewNameProvided = -not [string]::IsNullOrWhiteSpace($DataViewNameValue)
        DataViewTimeField   = '@timestamp'
        WorkDirFull         = $workDirFull
        LogPath             = Join-Path $workDirFull 'import.log'
        JqCommand           = $jqCommand
        Utf8NoBom           = $utf8NoBom
        Utf8Strict          = $utf8Strict
        HttpHandler         = $httpResources.Handler
        HttpClient          = $httpResources.Client
        AuthHeader          = Get-BasicAuthHeader -User $ElasticUserValue -Password $effectivePassword
        Stopwatch           = [System.Diagnostics.Stopwatch]::StartNew()
    }

    [System.IO.File]::WriteAllText($script:Runtime.LogPath, '', $script:Runtime.Utf8NoBom)

    return $script:Runtime
}

function Invoke-ElasticRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$ContentType,
        [string]$InputFilePath,
        [string]$Body,
        [int[]]$AcceptHttpStatus = @(200,201)
    )

    $contentTypeWithUtf8 = Get-ContentTypeWithUtf8 -ContentType $ContentType
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method.ToUpperInvariant()), $Url)
    $request.Headers.Authorization = $script:Runtime.AuthHeader

    if ($PSBoundParameters.ContainsKey('InputFilePath')) {
        $request.Content = [System.Net.Http.StreamContent]::new([System.IO.File]::OpenRead($InputFilePath))
        if (-not [string]::IsNullOrWhiteSpace($contentTypeWithUtf8)) {
            $request.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($contentTypeWithUtf8)
        }
    }
    elseif ($PSBoundParameters.ContainsKey('Body')) {
        $request.Content = [System.Net.Http.StringContent]::new($Body, $script:Runtime.Utf8NoBom)
        if (-not [string]::IsNullOrWhiteSpace($contentTypeWithUtf8)) {
            $request.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($contentTypeWithUtf8)
        }
    }

    $response = $null
    $responseBody = ''

    try {
        # Use HttpClient directly so Elasticsearch requests do not depend on temp response files.
        $response = $script:Runtime.HttpClient.SendAsync($request).GetAwaiter().GetResult()
        $statusCode = [int]$response.StatusCode

        if ($null -ne $response.Content) {
            $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        }
    }
    catch {
        $hint = ''
        if ($_.Exception -is [System.OperationCanceledException]) {
            $hint = ' Request timed out. Increase -HttpTimeoutMinutes or reduce -DocsPerBulk.'
        }

        Write-Log -Level 'ERROR' -Message ('HTTP request failed for {0} {1}. {2}{3}' -f $Method.ToUpperInvariant(), $Url, $_.Exception.Message, $hint)
        throw "HTTP request failed for $Method $Url. $($_.Exception.Message)$hint"
    }
    finally {
        if ($null -ne $response) {
            $response.Dispose()
        }
        $request.Dispose()
    }

    if ($statusCode -notin $AcceptHttpStatus) {
        Write-Log -Level 'ERROR' -Message ("HTTP {0} {1} -> {2}. Body: {3}" -f $Method.ToUpperInvariant(), $Url, $statusCode, (Get-TrimmedSingleLine -Text $responseBody -MaxLength 600))
        throw "HTTP $statusCode from Elasticsearch. Body: $responseBody"
    }

    Write-Log -Level 'INFO' -Message ("HTTP {0} {1} -> {2}" -f $Method.ToUpperInvariant(), $Url, $statusCode)

    return [pscustomobject]@{
        StatusCode = $statusCode
        Body       = $responseBody
    }
}

function Invoke-KibanaRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Body,
        [string]$ContentType = 'application/json',
        [int[]]$AcceptHttpStatus = @(200)
    )

    if ($script:Runtime.SkipDataViewCreation) {
        throw 'Kibana request is unavailable because Data View creation is disabled.'
    }

    $url = "$($script:Runtime.KibanaApiRoot)/$($Path.TrimStart('/'))"
    $contentTypeWithUtf8 = Get-ContentTypeWithUtf8 -ContentType $ContentType
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method.ToUpperInvariant()), $url)
    $request.Headers.Authorization = $script:Runtime.AuthHeader
    [void]$request.Headers.TryAddWithoutValidation('kbn-xsrf', 'true')

    if ($PSBoundParameters.ContainsKey('Body')) {
        $request.Content = [System.Net.Http.StringContent]::new($Body, $script:Runtime.Utf8NoBom)
        if (-not [string]::IsNullOrWhiteSpace($contentTypeWithUtf8)) {
            $request.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($contentTypeWithUtf8)
        }
    }

    $response = $null
    $responseBody = ''

    try {
        $response = $script:Runtime.HttpClient.SendAsync($request).GetAwaiter().GetResult()
        $statusCode = [int]$response.StatusCode

        if ($null -ne $response.Content) {
            $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        }
    }
    catch {
        Write-Log -Level 'ERROR' -Message ('Kibana request failed for {0} {1}. {2}' -f $Method.ToUpperInvariant(), $url, $_.Exception.Message)
        throw "Kibana request failed for $Method $url. $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $response) {
            $response.Dispose()
        }

        $request.Dispose()
    }

    if ($statusCode -notin $AcceptHttpStatus) {
        Write-Log -Level 'ERROR' -Message ('Kibana HTTP {0} {1} -> {2}. Body: {3}' -f $Method.ToUpperInvariant(), $url, $statusCode, (Get-TrimmedSingleLine -Text $responseBody -MaxLength 600))
        throw "Kibana HTTP $statusCode. Body: $responseBody"
    }

    Write-Log -Level 'INFO' -Message ('Kibana HTTP {0} {1} -> {2}' -f $Method.ToUpperInvariant(), $url, $statusCode)

    return [pscustomobject]@{
        StatusCode = $statusCode
        Body       = $responseBody
    }
}

function Get-KibanaDataViews {
    $result = Invoke-KibanaRequest -Method 'GET' -Path 'data_views'

    try {
        $json = $result.Body | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    }
    catch {
        throw "Cannot parse Kibana Data Views response. $($_.Exception.Message)"
    }

    if ($null -eq $json.data_view) {
        return @()
    }

    return @($json.data_view)
}

function Find-KibanaDataViewByTitle {
    param([Parameter(Mandatory = $true)][string]$Title)

    $matches = @(Get-KibanaDataViews | Where-Object { $_.title -eq $Title })
    if ($matches.Count -eq 0) {
        return $null
    }

    return $matches[0]
}

function New-KibanaDataViewBody {
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$TimeFieldName,
        [string]$Name
    )

    $dataView = @{
        title         = $Title
        timeFieldName = $TimeFieldName
    }

    if (-not [string]::IsNullOrWhiteSpace($Name)) {
        $dataView.name = $Name
    }

    return (@{ data_view = $dataView } | ConvertTo-Json -Depth 10)
}

function ConvertFrom-KibanaDataViewResponse {
    param([Parameter(Mandatory = $true)][string]$ResponseBody)

    try {
        $json = $ResponseBody | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    }
    catch {
        throw "Cannot parse Kibana Data View response. $($_.Exception.Message)"
    }

    if ($null -eq $json.data_view) {
        throw 'Kibana Data View response does not contain a data_view object.'
    }

    return $json.data_view
}

function Ensure-KibanaDataView {
    if ($script:Runtime.SkipDataViewCreation) {
        return [pscustomobject]@{
            Status        = 'skipped'
            Id            = ''
            Title         = ''
            Name          = ''
            TimeFieldName = ''
        }
    }

    Write-Log -Level 'INFO' -Message ('Ensuring Kibana Data View title={0}; name={1}; time field={2}' -f $script:Runtime.DataViewPattern, $script:Runtime.DataViewName, $script:Runtime.DataViewTimeField)

    $existing = Find-KibanaDataViewByTitle -Title $script:Runtime.DataViewPattern
    $desiredName = if ($script:Runtime.DataViewNameProvided) { $script:Runtime.DataViewName } elseif ($null -ne $existing -and -not [string]::IsNullOrWhiteSpace($existing.name)) { $existing.name } else { $script:Runtime.DataViewName }
    $requestBody = New-KibanaDataViewBody -Title $script:Runtime.DataViewPattern -Name $desiredName -TimeFieldName $script:Runtime.DataViewTimeField

    if ($null -eq $existing) {
        $create = Invoke-KibanaRequest -Method 'POST' -Path 'data_views/data_view' -Body $requestBody -AcceptHttpStatus @(200, 201)
        $created = ConvertFrom-KibanaDataViewResponse -ResponseBody $create.Body

        return [pscustomobject]@{
            Status        = 'created'
            Id            = $created.id
            Title         = $created.title
            Name          = $created.name
            TimeFieldName = $created.timeFieldName
        }
    }

    $needsTimeFieldUpdate = ($existing.timeFieldName -ne $script:Runtime.DataViewTimeField)
    $needsNameUpdate = ($script:Runtime.DataViewNameProvided -and ($existing.name -ne $script:Runtime.DataViewName))

    if (-not ($needsTimeFieldUpdate -or $needsNameUpdate)) {
        return [pscustomobject]@{
            Status        = 'existing'
            Id            = $existing.id
            Title         = $existing.title
            Name          = $existing.name
            TimeFieldName = $existing.timeFieldName
        }
    }

    $update = Invoke-KibanaRequest -Method 'POST' -Path ('data_views/data_view/{0}' -f $existing.id) -Body $requestBody -AcceptHttpStatus @(200)
    $updated = ConvertFrom-KibanaDataViewResponse -ResponseBody $update.Body

    return [pscustomobject]@{
        Status        = 'updated'
        Id            = $updated.id
        Title         = $updated.title
        Name          = $updated.name
        TimeFieldName = $updated.timeFieldName
    }
}

function New-IndexBodyJson {
@'
{
    "settings": {
        "index": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "-1",
            "query": {
                "default_field": [
                    "event_fulltext",
                    "*"
                ]
            },
            "mapping": {
                "total_fields": {
                    "limit": 20000
                }
            }
        }
    },
    "mappings": {
        "_meta": {
            "created_by": "Import-NdjsonToElastic.ps1",
            "note": "ETW NDJSON import. @timestamp is copied from TimeStamp. event_fulltext is generated by jq from all scalar paths and values."
        },
        "date_detection": false,
        "numeric_detection": false,
        "dynamic": true,
        "dynamic_templates": [
            {
                "strings_as_text_and_keyword": {
                    "match_mapping_type": "string",
                    "mapping": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 8191
                            }
                        }
                    }
                }
            }
        ],
        "properties": {
            "@timestamp": {
                "type": "date_nanos",
                "format": "strict_date_optional_time_nanos||strict_date_optional_time||epoch_millis"
            },
            "TimeStamp": {
                "type": "date_nanos",
                "format": "strict_date_optional_time_nanos||strict_date_optional_time||epoch_millis"
            },
            "event_fulltext": {
                "type": "text"
            },
            "EventId": {
                "type": "long"
            },
            "EventDataLength": {
                "type": "long"
            },
            "Opcode": {
                "type": "long"
            },
            "PointerSize": {
                "type": "long"
            },
            "ProcessID": {
                "type": "long"
            },
            "ThreadID": {
                "type": "long"
            },
            "XmlEventData": {
                "type": "object",
                "dynamic": true
            }
        }
    }
}
'@
}

function New-JqFilterText {
@'
def scalar_text:
    [
        paths(scalars) as $p
        | (($p | map(tostring) | join(".")), (getpath($p) | tostring))
    ]
    | join(" ");

(."@timestamp" = (.TimeStamp // null))
| (.event_fulltext = scalar_text)
| {"index": {}}, .
'@
}

function Get-BulkItemErrorSummary {
    param([Parameter(Mandatory = $true)][object]$BulkResponse)

    foreach ($item in $BulkResponse.items) {
        foreach ($operationName in @('index', 'create', 'update', 'delete')) {
            $operation = $item.$operationName
            if ($null -ne $operation -and $null -ne $operation.error) {
                return ('{0} status={1} type={2} reason={3}' -f
                    $operationName,
                    $operation.status,
                    $operation.error.type,
                    (Get-TrimmedSingleLine -Text $operation.error.reason -MaxLength 400))
            }
        }
    }

    return 'No per-item error details were returned by Elasticsearch.'
}

function Test-ElasticConnection {
    $cluster = Invoke-ElasticRequest -Method 'GET' -Url "$($script:Runtime.ElasticUrlNorm)/"

    try {
        $clusterInfo = $cluster.Body | ConvertFrom-Json -ErrorAction Stop
        Write-Log -Level 'INFO' -Message ('Elasticsearch is reachable. cluster={0} version={1}' -f $clusterInfo.cluster_name, $clusterInfo.version.number)
    }
    catch {
        Write-Log -Level 'INFO' -Message 'Elasticsearch is reachable.'
    }
}

function Test-TargetIndexExists {
    $indexCheck = Invoke-ElasticRequest -Method 'GET' -Url "$($script:Runtime.ElasticUrlNorm)/$($script:Runtime.IndexName)" -AcceptHttpStatus @(200, 404)
    return ($indexCheck.StatusCode -eq 200)
}

function Initialize-TargetIndex {
    param([Parameter(Mandatory = $true)][bool]$DeleteExisting)

    if ($DeleteExisting) {
        Write-Log -Level 'INFO' -Message ("Index '{0}' exists. Deleting because -Recreate was specified..." -f $script:Runtime.IndexName)
        [void](Invoke-ElasticRequest -Method 'DELETE' -Url "$($script:Runtime.ElasticUrlNorm)/$($script:Runtime.IndexName)" -AcceptHttpStatus @(200, 404))
    }

    $indexBodyPath = Join-Path $script:Runtime.WorkDirFull 'create_index_body.json'
    Write-Utf8File -Path $indexBodyPath -Content (New-IndexBodyJson)

    Write-Log -Level 'INFO' -Message ("Creating index '{0}'..." -f $script:Runtime.IndexName)
    $create = Invoke-ElasticRequest -Method 'PUT' -Url "$($script:Runtime.ElasticUrlNorm)/$($script:Runtime.IndexName)" -ContentType 'application/json' -InputFilePath $indexBodyPath
    Write-Log -Level 'INFO' -Message ('Create index response: {0}' -f (Get-TrimmedSingleLine -Text $create.Body -MaxLength 600))
}

function Restore-IndexRefreshState {
    param([Parameter(Mandatory = $true)][string]$Name)

    $settingsBody = @'
{
  "index": {
    "refresh_interval": "1s"
  }
}
'@

    $settingsPath = Join-Path $script:Runtime.WorkDirFull 'restore_settings_body.json'
    Write-Utf8File -Path $settingsPath -Content $settingsBody

    Write-Log -Level 'INFO' -Message ("Restoring refresh_interval and refreshing index '{0}'..." -f $Name)
    [void](Invoke-ElasticRequest -Method 'PUT' -Url "$($script:Runtime.ElasticUrlNorm)/$Name/_settings" -ContentType 'application/json' -InputFilePath $settingsPath)
    [void](Invoke-ElasticRequest -Method 'POST' -Url "$($script:Runtime.ElasticUrlNorm)/$Name/_refresh")
}

function Invoke-BulkChunk {
    param(
        [Parameter(Mandatory = $true)][string]$BulkPath,
        [Parameter(Mandatory = $true)][int]$BatchNo,
        [Parameter(Mandatory = $true)][int]$DocCount
    )

    $url = "$($script:Runtime.ElasticUrlNorm)/$($script:Runtime.IndexName)/_bulk?filter_path=errors,took,items.*.error,items.*.status"

    Write-Log -Level 'INFO' -Message ('Uploading batch={0} docs={1} chunk={2}' -f $BatchNo, $DocCount, $BulkPath)

    $result = Invoke-ElasticRequest -Method 'POST' -Url $url -ContentType 'application/x-ndjson' -InputFilePath $BulkPath

    try {
        $json = $result.Body | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $rawPath = Join-Path $script:Runtime.WorkDirFull ('bulk_response_parse_failed_{0:D6}.txt' -f $BatchNo)
        Write-Utf8File -Path $rawPath -Content $result.Body
        Write-Log -Level 'ERROR' -Message ('Cannot parse Elasticsearch bulk response for batch={0}. Raw response saved to {1}' -f $BatchNo, $rawPath)
        throw "Cannot parse Elasticsearch bulk response for batch $BatchNo. Saved raw response to $rawPath"
    }

    if ($json.errors -eq $true) {
        $errPath = Join-Path $script:Runtime.WorkDirFull ('bulk_errors_{0:D6}.json' -f $BatchNo)
        Write-Utf8File -Path $errPath -Content $result.Body
        $errorSummary = Get-BulkItemErrorSummary -BulkResponse $json
        Write-Log -Level 'ERROR' -Message ('Bulk API returned item errors on batch={0} docs={1} chunk={2}. First error: {3}. Filtered response: {4}' -f $BatchNo, $DocCount, $BulkPath, $errorSummary, $errPath)
        throw "Bulk API returned item errors on batch $BatchNo. First error: $errorSummary. Saved filtered response to $errPath. Failed chunk retained at: $BulkPath"
    }

    Write-Log -Level 'INFO' -Message ('OK batch={0} docs={1} took={2}ms' -f $BatchNo, $DocCount, $json.took)
}

function Invoke-NdjsonBulkImport {
    param([Parameter(Mandatory = $true)][string]$InputPath)

    $jqFilterPath = Join-Path $script:Runtime.WorkDirFull 'ndjson_to_bulk.jq'
    Write-Utf8File -Path $jqFilterPath -Content (New-JqFilterText)

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $script:Runtime.JqCommand.Source
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = $script:Runtime.Utf8Strict
    $psi.StandardErrorEncoding = $script:Runtime.Utf8Strict

    foreach ($argument in @('-c', '-f', $jqFilterPath, $InputPath)) {
        $psi.ArgumentList.Add($argument)
    }

    Write-Log -Level 'INFO' -Message ('Starting jq transform with {0} for {1}' -f $script:Runtime.JqCommand.Source, $InputPath)

    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($null -eq $proc) {
        throw 'Failed to start jq process.'
    }

    $stderrTask = $proc.StandardError.ReadToEndAsync()

    $batchNo = 1
    $docsInBatch = 0
    $totalDocs = 0
    $uploadedBatches = 0
    $bulkLineNo = 0
    $chunkPath = Join-Path $script:Runtime.WorkDirFull ('bulk_{0:D6}.ndjson' -f $batchNo)
    $writer = [System.IO.StreamWriter]::new($chunkPath, $false, $script:Runtime.Utf8NoBom, 1024 * 1024)

    try {
        while ($null -ne ($line = $proc.StandardOutput.ReadLine())) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $writer.WriteLine($line)
            $bulkLineNo++

            # jq emits exactly two lines per source document: action line + source line.
            if (($bulkLineNo % 2) -eq 0) {
                $docsInBatch++
                $totalDocs++

                if (($totalDocs % 50000) -eq 0) {
                    Write-Log -Level 'INFO' -Message ('Prepared {0} documents...' -f $totalDocs)
                }

                if ($docsInBatch -ge $script:Runtime.DocsPerBulk) {
                    $writer.Dispose()
                    $writer = $null

                    Invoke-BulkChunk -BulkPath $chunkPath -BatchNo $batchNo -DocCount $docsInBatch
                    $uploadedBatches++

                    if (-not $KeepChunks) {
                        Remove-Item -LiteralPath $chunkPath -Force
                    }

                    $batchNo++
                    $docsInBatch = 0
                    $chunkPath = Join-Path $script:Runtime.WorkDirFull ('bulk_{0:D6}.ndjson' -f $batchNo)
                    $writer = [System.IO.StreamWriter]::new($chunkPath, $false, $script:Runtime.Utf8NoBom, 1024 * 1024)
                }
            }
        }

        $proc.WaitForExit()
        $stderr = $stderrTask.GetAwaiter().GetResult()

        if ($proc.ExitCode -ne 0) {
            $stderrPath = Join-Path $script:Runtime.WorkDirFull 'jq.stderr.txt'
            Write-Utf8File -Path $stderrPath -Content $stderr
            Write-Log -Level 'ERROR' -Message ('jq failed with exit code {0}. Saved stderr to {1}. stderr: {2}' -f $proc.ExitCode, $stderrPath, (Get-TrimmedSingleLine -Text $stderr -MaxLength 600))
            throw "jq failed with exit code $($proc.ExitCode). Saved stderr to $stderrPath"
        }

        if (($bulkLineNo % 2) -ne 0) {
            throw 'Generated bulk stream has an odd number of lines. Action/source pairs are broken.'
        }

        if ($docsInBatch -gt 0) {
            $writer.Dispose()
            $writer = $null

            Invoke-BulkChunk -BulkPath $chunkPath -BatchNo $batchNo -DocCount $docsInBatch
            $uploadedBatches++

            if (-not $KeepChunks) {
                Remove-Item -LiteralPath $chunkPath -Force
            }
        }
        else {
            if ($null -ne $writer) {
                $writer.Dispose()
                $writer = $null
            }

            if ((Test-Path -LiteralPath $chunkPath) -and (-not $KeepChunks)) {
                Remove-Item -LiteralPath $chunkPath -Force
            }
        }
    }
    finally {
        if ($null -ne $writer) {
            $writer.Dispose()
        }

        if ($null -ne $proc -and (-not $proc.HasExited)) {
            try {
                $proc.Kill()
            }
            catch {
            }
        }
    }

    return [pscustomobject]@{
        TotalDocs       = $totalDocs
        UploadedBatches = $uploadedBatches
    }
}

function Write-ImportSummary {
    param(
        [Parameter(Mandatory = $true)][int]$TotalDocs,
        [Parameter(Mandatory = $true)][int]$UploadedBatches,
        [AllowNull()][object]$DataViewResult,
        [string]$DataViewError = ''
    )

    $elapsed = $script:Runtime.Stopwatch.Elapsed
    $elapsedText = ConvertTo-DurationString -Duration $elapsed
    $docsPerSecond = 0

    if ($elapsed.TotalSeconds -gt 0) {
        $docsPerSecond = [Math]::Round(($TotalDocs / $elapsed.TotalSeconds), 2)
    }

    Write-Log -Level 'INFO' -Message ('DONE. Imported source documents: {0}; uploaded batches: {1}; elapsed: {2}; throughput: {3} docs/s' -f $TotalDocs, $UploadedBatches, $elapsedText, $docsPerSecond)

    try {
        $count = Invoke-ElasticRequest -Method 'GET' -Url "$($script:Runtime.ElasticUrlNorm)/$($script:Runtime.IndexName)/_count?pretty"
        Write-Host 'Count response:'
        Write-Host $count.Body
        Write-Log -Level 'INFO' -Message ('Count response: {0}' -f (Get-TrimmedSingleLine -Text $count.Body -MaxLength 600))
    }
    catch {
        Write-Log -Level 'WARN' -Message ('Failed to read final document count. {0}' -f $_.Exception.Message)
    }

    try {
        $cat = Invoke-ElasticRequest -Method 'GET' -Url "$($script:Runtime.ElasticUrlNorm)/_cat/indices/$($script:Runtime.IndexName)?v"
        Write-Host 'Index status:'
        Write-Host $cat.Body
        Write-Log -Level 'INFO' -Message ('Index status: {0}' -f (Get-TrimmedSingleLine -Text $cat.Body -MaxLength 600))
    }
    catch {
        Write-Log -Level 'WARN' -Message ('Failed to read final index status. {0}' -f $_.Exception.Message)
    }

    if ($script:Runtime.SkipDataViewCreation) {
        Write-Log -Level 'INFO' -Message 'Kibana Data View: skipped because -SkipDataViewCreation was specified.'
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($DataViewError)) {
        Write-Log -Level 'ERROR' -Message ('Kibana Data View failed for title={0}; name={1}; time field={2}. {3}' -f $script:Runtime.DataViewPattern, $script:Runtime.DataViewName, $script:Runtime.DataViewTimeField, $DataViewError)
        return
    }

    if ($null -eq $DataViewResult) {
        Write-Log -Level 'WARN' -Message ('Kibana Data View status is unknown for title={0}.' -f $script:Runtime.DataViewPattern)
        return
    }

    Write-Log -Level 'INFO' -Message ('Kibana Data View {0}: title={1}; name={2}; time field={3}; id={4}' -f $DataViewResult.Status, $DataViewResult.Title, $DataViewResult.Name, $DataViewResult.TimeFieldName, $DataViewResult.Id)
}

$restoreRefreshInterval = $false
$dataViewResult = $null
$dataViewError = ''

try {
    $runtime = Initialize-ImportRuntime -NdjsonPathValue $NdjsonPath -IndexNameValue $IndexName -ElasticUrlValue $ElasticUrl -KibanaUrlValue $KibanaUrl -ElasticUserValue $ElasticUser -ElasticPasswordValue $ElasticPassword -DocsPerBulkValue $DocsPerBulk -HttpTimeoutMinutesValue $HttpTimeoutMinutes -DataViewPatternValue $DataViewPattern -DataViewNameValue $DataViewName -SkipDataViewCreationValue:$SkipDataViewCreation -WorkDirValue $WorkDir

    Write-Log -Level 'INFO' -Message ('Input NDJSON : {0}' -f $runtime.NdjsonPathFull)
    Write-Log -Level 'INFO' -Message ('Input size   : {0}' -f (ConvertTo-SizeString -Bytes $runtime.NdjsonFileSizeBytes))
    Write-Log -Level 'INFO' -Message ('Index        : {0}' -f $runtime.IndexName)
    Write-Log -Level 'INFO' -Message ('Elasticsearch: {0}' -f $runtime.ElasticUrlNorm)
    if ($runtime.SkipDataViewCreation) {
        Write-Log -Level 'INFO' -Message 'Kibana Data View: disabled for this run.'
    }
    else {
        Write-Log -Level 'INFO' -Message ('Kibana       : {0}' -f $runtime.KibanaUrlNorm)
        Write-Log -Level 'INFO' -Message ('Data View    : title={0}; name={1}; time field={2}' -f $runtime.DataViewPattern, $runtime.DataViewName, $runtime.DataViewTimeField)
    }
    Write-Log -Level 'INFO' -Message ('WorkDir      : {0}' -f $runtime.WorkDirFull)
    Write-Log -Level 'INFO' -Message ('DocsPerBulk  : {0}' -f $runtime.DocsPerBulk)
    Write-Log -Level 'INFO' -Message ('HTTP timeout : {0} minute(s)' -f $runtime.HttpTimeoutMinutes)
    Write-Log -Level 'INFO' -Message ('jq           : {0}' -f $runtime.JqCommand.Source)

    Test-ElasticConnection

    $indexExists = Test-TargetIndexExists
    if ($indexExists -and (-not $Recreate)) {
        throw "Index '$($runtime.IndexName)' already exists. Re-run with -Recreate if you want to delete and recreate it."
    }

    $inputSource = Resolve-NdjsonImportSource -Path $runtime.NdjsonPathFull -WorkDirectory $runtime.WorkDirFull
    Write-Log -Level 'INFO' -Message ('Detected input encoding: {0}; BOM={1}; normalized={2}' -f $inputSource.DetectedEncoding, $inputSource.HasBom, $inputSource.WasNormalized)
    if ($inputSource.WasNormalized) {
        Write-Log -Level 'INFO' -Message ('Using normalized UTF-8 import source: {0}' -f $inputSource.ImportPath)
    }

    Initialize-TargetIndex -DeleteExisting:$indexExists
    $restoreRefreshInterval = $true

    $importResult = Invoke-NdjsonBulkImport -InputPath $inputSource.ImportPath

    Restore-IndexRefreshState -Name $runtime.IndexName
    $restoreRefreshInterval = $false

    if (-not $runtime.SkipDataViewCreation) {
        try {
            $dataViewResult = Ensure-KibanaDataView
        }
        catch {
            $dataViewError = $_.Exception.Message
        }
    }

    Write-ImportSummary -TotalDocs $importResult.TotalDocs -UploadedBatches $importResult.UploadedBatches -DataViewResult $dataViewResult -DataViewError $dataViewError

    if (-not [string]::IsNullOrWhiteSpace($dataViewError)) {
        throw "Import succeeded, but failed to create or update Kibana Data View. $dataViewError"
    }
}
catch {
    Write-Log -Level 'ERROR' -Message $_.Exception.Message
    throw
}
finally {
    if ($restoreRefreshInterval -and $null -ne $script:Runtime) {
        try {
            Restore-IndexRefreshState -Name $script:Runtime.IndexName
        }
        catch {
            Write-Log -Level 'WARN' -Message ('Failed to restore refresh settings for index ''{0}'' during cleanup. {1}' -f $script:Runtime.IndexName, $_.Exception.Message)
        }
    }

    if ($null -ne $script:Runtime) {
        if ($null -ne $script:Runtime.Stopwatch -and $script:Runtime.Stopwatch.IsRunning) {
            $script:Runtime.Stopwatch.Stop()
        }

        if ($null -ne $script:Runtime.HttpClient) {
            $script:Runtime.HttpClient.Dispose()
        }

        if ($null -ne $script:Runtime.HttpHandler) {
            $script:Runtime.HttpHandler.Dispose()
        }

        if (-not [string]::IsNullOrWhiteSpace($script:Runtime.LogPath)) {
            Write-Host ('Log file: {0}' -f $script:Runtime.LogPath)
        }
    }
}
