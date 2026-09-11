# Biztonsági megjegyzések – 0.1.0

## Emelt jogosultság

A prototípusban `full_access: true`, `kernel_modules: true` és `apparmor: false`
szerepel. A Védett mód kikapcsolása teljes hardverhozzáférést és kernelmodul-
betöltési lehetőséget adhat a konténernek. Ez nagyobb jogosultság annál, amit
egy egyszerű TCP-proxy igényelne; a PPP-eszköz létrehozása és a különböző HA OS
kernelkialakítások kipróbálása miatt szerepel az első kísérleti kiadásban.

**A saját hálózati névtér nem helyettesíti a biztonsági sandboxot.** A kód
nem lép át a gazdarendszer hálózati névterébe, és nem állítja át a HA útvonalait,
de egy rosszindulatúan módosított vagy sérülékeny privilegizált addon komoly
kárt okozhat. A kódot áttekintés és mentés nélkül ne indítsd el.

Sikeres kompatibilitási teszt után a jogosultságokat célszerű a konkrét
környezethez szűkíteni: előre létező `/dev/ppp` eszközátadás, `NET_ADMIN` és
`NET_RAW`, lehetőség szerint modulbetöltés nélkül és külön AppArmor-profillal.
Ez nincs automatikusan elvégezve vagy éles környezetben tesztelve a 0.1.0-ban.

## Titkok

Valódi PSK, jelszó, felhasználónév vagy szolgáltatói konfiguráció ne kerüljön
GitHubra, GitHub Actions secretbe sem szükséges tenni. A példaadatok nem működő
hozzáférések. A futásidejű titkos fájlok 0600 joggal a `/tmp/ha-l2tp` alatt
keletkeznek; a HA konfigurációban engedélyezett `/tmp` tmpfs ezt memóriában tartja.
A HA által tárolt `options.json` ettől még tartalmazza az adatokat, és a mentések
is érzékenyek lehetnek. A base64 PSK-ábrázolás csak fájlformátum, **nem titkosítás**.

Nincs shellbe behelyettesített felhasználói szöveg. A titkokat a program nem
adja parancssori argumentumként a VPN-folyamatoknak. A naplóban az ismert
hitelesítési értékeket szűri, de megosztás előtt mindig ellenőrizd a naplót.

## Hálózat

A belső TCP-átjáró nem használ külön alkalmazásszintű hitelesítést.
Alapból nincs LAN-on publikált port; az IPv4 forráscímeket ACL korlátozza.
Ne publikáld az átjárót az interneten. A publikus VPN-kiszolgálóhoz nincs szükség
új, routeren beállított bejövő porttovábbításra a HA oldalán.

A kód a PPP-interfészhez köti az adapter felé nyitott socketet, és konténeren
belüli tűzfalszabályokat telepít a titkosítatlan L2TP és a VPN-en kívüli
adapterforgalom elutasítására. Ezeket éles tunnel-vesztési helyzetben még
ellenőrizni kell. A diagnosztika és az offline teszt nem helyettesíti a
hálózati csomagszintű ellenőrzést.

Az IKEv1/L2TP örökölt megoldás; a régi MODP1024/3DES ajánlatok csak explicit
kompatibilitási kapcsolóval érhetők el. Ne engedélyezd őket szükség nélkül.
Későbbi üzemeltetési feladat a base image és a VPN-csomagok biztonsági frissítése.

## Fűtési rendszer

A távoli olvasást teszteld először. A VPN kiesésétől függetlenül a kazán helyi,
biztonságos szabályozásának működnie kell. Ne használd ezt a prototípust
biztonsági funkció vagy egyetlen hőszabályozási útvonal helyettesítésére.
