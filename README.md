
# DriverAuditLab (Windows • C • Win32)

Ferramenta **educacional e defensiva** que enumera **drivers carregados** e verifica **assinatura digital** de cada binário, gerando relatório em tela e CSV.
Não faz alterações no sistema.

## Recursos
- Enumera drivers via `EnumDeviceDrivers` (Psapi).
- Obtém caminho do arquivo do driver e metadados (empresa, versão).
- Verifica assinatura com `WinVerifyTrust` (WinTrust).
- Exporta CSV opcional.

## Build
- Windows 10/11, Visual Studio 2022.
- Abra `DriverAudit.sln`, selecione `x64 | Release` e **Build**.

## Uso
```bat
x64\Release\DriverAudit.exe
x64\Release\DriverAudit.exe --csv drivers.csv
```

## Saída (exemplo)
```
0xFFFFF80E2B2C0000 | C:\Windows\System32\drivers\wd\driver.sys | Signed: YES | Company: Microsoft Corporation | FileVer: 10.0.22621.1
...
```

## Licença
MIT (c) 2025. Uso educacional e de auditoria.
