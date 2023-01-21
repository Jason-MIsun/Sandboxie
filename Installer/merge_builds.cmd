@ECHO OFF

call %~dp0get_openssl.cmd

call %~dp0get_7zip.cmd

cmd.exe /c %~dp0copy_build.cmd x64
