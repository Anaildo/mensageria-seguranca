$ErrorActionPreference = 'Stop'
if (Test-Path certs/server.p12) { throw 'Certificado existente. Preserve-o ou escolha conscientemente outro diretorio; nao sera sobrescrito.' }
if (-not $env:MENSAGERIA_STORE_PASSWORD) { throw 'Defina MENSAGERIA_STORE_PASSWORD antes de executar.' }
$keytoolCommand = Get-Command keytool -ErrorAction SilentlyContinue
if ($keytoolCommand) { $keytoolPath = $keytoolCommand.Source }
else {
    if (-not $env:JAVA_HOME) {
        $ErrorActionPreference = 'Continue'
        $settings = (& java -XshowSettings:properties -version 2>&1 | Out-String)
        $ErrorActionPreference = 'Stop'
        if ($settings -match 'java.home\s*=\s*([^\r\n]+)') { $env:JAVA_HOME = $Matches[1].Trim() }
    }
    if (-not $env:JAVA_HOME) { throw 'JDK nao localizado; configure JAVA_HOME.' }
    $keytoolPath = Join-Path $env:JAVA_HOME 'bin/keytool.exe'
}
New-Item -ItemType Directory -Force certs | Out-Null
& $keytoolPath -genkeypair -alias server -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 365 -dname 'CN=Mensageria Academica' -storetype PKCS12 -keystore certs/server.p12 -storepass:env MENSAGERIA_STORE_PASSWORD -keypass:env MENSAGERIA_STORE_PASSWORD
if ($LASTEXITCODE -ne 0) { throw 'Falha ao gerar certificado' }
& $keytoolPath -exportcert -rfc -alias server -keystore certs/server.p12 -storepass:env MENSAGERIA_STORE_PASSWORD -file certs/server.crt
if ($LASTEXITCODE -ne 0) { throw 'Falha ao exportar certificado' }
