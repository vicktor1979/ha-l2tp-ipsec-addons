# Eredet és komponensek

Ez az addon újonnan írt implementáció a beszélgetésben felmerült
L2TP/IPsec + PSK + felhasználónév/jelszó használati esetre.

A koncepcióhoz kapcsolódó kiinduló projekt:
https://github.com/ubergarm/l2tp-ipsec-vpn-client

Nem tartalmazza változatlanul annak Alpine 3.8-as Dockerfile-ját vagy
startup.sh fájlját. Az IPsec és PPP konfigurációs kulcsnevek a használt
programok szabványos beállításai.

A Docker-kép Alpine Linuxból telepíti a strongSwan, xl2tpd, PPP, iproute2,
iptables, kmod, Python és tini csomagokat. Ezek saját licenceik szerint
használhatók; a repository MIT licence kizárólag a repository saját
forrásfájljaira vonatkozik, a csomagok licenceit nem írja felül.
