
Set WshShell = CreateObject("WScript.Shell")

WshShell.CurrentDirectory = "C:\xampp\htdocs\org_fee_system"

WshShell.Run """C:\xampp\php\php.exe"" ""C:\xampp\htdocs\org_fee_system\scripts\monitor.php""", 0, False

Set WshShell = Nothing