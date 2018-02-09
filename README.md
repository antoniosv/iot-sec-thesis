IoT LAN
network: MCLAB_IoTHome
pw: BDAB8ED4D2

----Useful commands----

Address for openHAB in raspberry pi:
http://192.168.1.245:8080/start/index

-- ssh connection to it:
ssh pi@192.168.1.245
raspberry

-- Things: Smart Office Indoor Station
Bridge: Netatmo API - netatmo:netatmoapi:829bfddf
MAC address: 70:ee:50:17:64:ce

-- restart openhab
sudo systemctl restart openhab.service

--docker commands in raspberry pi
docs: https://hub.docker.com/r/openhab/openhab/

$ docker exec -it openhab /bin/bash 
 > Gets me into the docker instance
$ docker exec -it openhab /openhab/runtime/bin/client
> Gets me into the karaf console

-- Change OpenHAB port to 8443 for HTTPS:
Edit /etc/default/openhab2
Replace OPENHAB_HTTP_PORT with OPENHAB_HTTPS_PORT
Then access openHAB2: https://localhost:8443/start/index

-- commit of authentication api for ESH
https://github.com/eclipse/smarthome/pull/2359#pullrequestreview-7199655

-- Security doc for ESH
https://docs.google.com/document/d/1Vja574ycr2f_1nDdhLheEPdqkRlsvHf2lc_byY2ahzc/edit#heading=h.8kha9nhne4ux

-- concepts:
ESH - Eclipse Smart Home
OH - openHAB

