Add-Type '[System.Runtime.InteropServices.DllImport("kernel32.dll")]public static extern uint SetThreadExecutionState(uint s);' -Name a -Namespace b

$ES_CONTINUOUS       = [uint32]2147483648
$ES_SYSTEM_REQUIRED  = [uint32]1
$ES_DISPLAY_REQUIRED = [uint32]2
$flags = $ES_CONTINUOUS -bor $ES_SYSTEM_REQUIRED -bor $ES_DISPLAY_REQUIRED

# Set once and keep the script alive
[b.a]::SetThreadExecutionState($flags)
while ($true) { Start-Sleep -Seconds 60 }

# Press Ctrl+C to stop; when the process exits the OS will revert sleep behavior.