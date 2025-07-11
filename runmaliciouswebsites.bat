@echo off
setlocal enabledelayedexpansion

REM Her domaini sırayla işle
for /f "delims=" %%d in (MalwareDomains.txt) do (
    echo Domain kontrol ediliyor: %%d
    ping -n 1 %%d >nul

    REM Eğer ping başarılıysa (hata kodu 0), siteyi aç
    if !errorlevel! == 0 (
        echo [✓] Ping başarılı, açılıyor: %%d
        start https://%%d
    ) else (
        echo [X] Ping başarısız: %%d
    )
)

REM Otomatik kapanır
