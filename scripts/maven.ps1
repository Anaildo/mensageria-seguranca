# Executa o Maven instalado ou a copia local preparada em .tools.
$ErrorActionPreference = 'Stop'
if (-not $env:JAVA_HOME) {
    # Windows PowerShell 5.1 trata stderr informativo do Java como ErrorRecord.
    $ErrorActionPreference = 'Continue'
    $settings = (& java -XshowSettings:properties -version 2>&1 | Out-String)
    $ErrorActionPreference = 'Stop'
    if ($settings -match 'java.home\s*=\s*([^\r\n]+)') { $env:JAVA_HOME = $Matches[1].Trim() }
}
$maven = Get-Command mvn.cmd -ErrorAction SilentlyContinue
if ($maven) { & $maven.Source @args; exit $LASTEXITCODE }
$localMaven = Join-Path $PSScriptRoot '../.tools/apache-maven-3.9.9/bin/mvn.cmd'
if (-not (Test-Path $localMaven)) { throw 'Instale Maven 3.9+ no PATH ou execute os comandos de instalacao local do README.' }
& $localMaven '-Dmaven.repo.local=.tools/repository' @args
exit $LASTEXITCODE
