#!/bin/bash

# Define the URL and payloads
LOGIN_URL="http://192.168.1.1/Forms/login_security_1"
POST_URL="http://192.168.1.1/Forms/home_wlan_1"

LOGIN_DATA="tipsFlag=1&timevalue=0&Login_Name=admin&Login_Pwd=Ha2S%2BeOKqmzA6nrlmTeh7w%3D%3D&uiWebLoginhiddenUsername=21232f297a57a5a743894a0e4a801fc3&uiWebLoginhiddenPassword=21232f297a57a5a743894a0e4a801fc3"

POST_DATA="wlanWEBFlag=0&AccessFlag=0&wlan_APenable=1&DfsTypeChangeFlag=0&countrySelect=93&Channel_ID=00000000&AdvWlan_slPower=High&BeaconInterval=100&RTSThreshold=2347&FragmentThreshold=2346&DTIM=1&WirelessMode=802.11b%2Bg%2Bn&WLANChannelBandwidth=Auto&WLANGuardInterval=Auto&WLANMCS=Auto&WLSSIDIndex=1&wlan_PerSSIDenable=1&ESSID_HIDE_Selection=0&UseWPS_Selection=0&WPSMode_Selection=1&ESSID=TP-LINK_DC334C&WEP_Selection=WPA2-PSK&TKIP_Selection=AES&PreSharedKey=ronbub050505&WDSMode_Selection=0&WLAN_FltActive=0&WLanLockFlag=0&wlanRadiusWEPFlag=0&SSIDCheckFlag=0"

# Step 1: Perform the login request and save the cookies
curl -X POST "$LOGIN_URL" \
-H "Host: 192.168.1.1" \
-H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0" \
-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
-H "Accept-Language: en-US,en;q=0.5" \
-H "Accept-Encoding: gzip, deflate" \
-H "Content-Type: application/x-www-form-urlencoded" \
-H "Origin: http://192.168.1.1" \
-H "Connection: keep-alive" \
-H "Referer: http://192.168.1.1/login_security.html" \
-H "Cookie: C0=%00; C1=%00" \
-H "Upgrade-Insecure-Requests: 1" \
-H "Priority: u=1" \
-d "$LOGIN_DATA" \
-c cookies.txt

# Step 2: Perform the second POST request using the cookies from the login
curl -X POST "$POST_URL" \
-H "Host: 192.168.1.1" \
-H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0" \
-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
-H "Accept-Language: en-US,en;q=0.5" \
-H "Accept-Encoding: gzip, deflate" \
-H "Content-Type: application/x-www-form-urlencoded" \
-H "Origin: http://192.168.1.1" \
-H "Connection: keep-alive" \
-H "Referer: http://192.168.1.1/basic/home_wlan.htm" \
-H "Upgrade-Insecure-Requests: 1" \
-H "Priority: u=4" \
-b cookies.txt \
-d "$POST_DATA"

