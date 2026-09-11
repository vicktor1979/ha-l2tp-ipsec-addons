# Biztonsági megjegyzések – 0.2.0

Kísérleti kód, független biztonsági audit nélkül. Üzemi fűtési környezetbe csak külön teszt és a kockázatok mérlegelése után illeszd. A veepin kriptográfiai megvalósításának helyességét nem auditáltuk; az upstream tesztállítás nem egyenértékű saját igazolással.

## Jogosultságok

A 0.1.0 széles rendszerjogai kikerültek. A manifestben `host_network: false`, `full_access: false`, `kernel_modules: false`, `apparmor: true` található. Csak `/dev/net/tun`, `NET_ADMIN` és `NET_RAW` kért. A VPN- és route-módosítások saját konténerhálózatban történnek. Nincs HA-/Supervisor-/Docker-API-hozzáférés és nincs további HA-adatkönyvtár csatolva.

Védett móddal kezdd a próbát. A célzott eszköz/capability engedélyezést az adott HA OS/Supervisor/AppArmor összeállításon külön igazolni kell. Ez nem jogosultság nélküli program: a konténerben rootként fut és saját hálózatot kezel.

## Titkok

A felhasználónév, a jelszó és a PSK a HA által átadott `/data/options.json` fájlból kerül a folyamat memóriájába. A motor privát standard-bemeneti pipe-on kapja meg ezeket, nem parancssori argumentumként vagy környezeti változóként. A program nem hoz létre további tartós titokfájlt, és a konfigurációobjektum repr-je sem tartalmazza a titkokat.

A HA saját konfigurációja és mentése ettől még tartalmazhatja a VPN-titkokat: a HA-adminisztrációt és a backupokat védeni kell. A logger ismert titkokat és több kódolt alakjukat maszkolja, de ez nem helyettesíti a napló kézi ellenőrzését, és nem garantálja az összes elképzelhető származtatott adat eltüntetését.

GitHubra, hibajegybe vagy Actions-be nem szükséges valódi VPN-adatot feltölteni. A csomag példáiban és tesztjeiben csak kitalált értékek szerepelnek.

## Hálózat

A proxy alapból nincs a HA-gazdagép/LAN portjára közzétéve. Az addonhálózaton elérhető, alkalmazásszintű forrás-IP engedélyezéssel. Másik HA-géphez tudatos portközzététel és konkrét `/32` engedély szükséges. A helyi TCP-protokoll nem hitelesített és nem TLS-titkosított. A VPN csak a VPN-kliens és a VPN-végpont közötti szakaszt titkosítja; a helyi relay és a szerver mögötti LAN külön bizalmi határ.

A proxy egyszerre egy klienssel működik, nem olvas eBUS-adatokat önállóan. A VPN-es socket interfészhez és forráscímhez kötött; hiba esetén bezár, nincs sima LAN-os kapcsolati tartalékút. A teljes HA-forgalomra és DNS-re nincs átirányítás. Az adapter /32 címe a konténerben VPN nélkül tiltó útvonalat kap.

Ne tedd a TCP-proxyportot vagy az adaptert közvetlenül az internetre. A helyi hálózati hozzáférés megfelelő tűzfal-korlátozása az üzemeltető feladata. A `0.0.0.0/0` engedélylistát a program elutasítja.

## Újrapróbálkozás és diagnosztika

Alapból csak diagnosztika fut, semmilyen VPN-hitelesítési kísérlet nélkül. VPN-módban korlátozott számú próbálkozás van; az azonosított hitelesítési hiba azonnali leállást okoz. A Watchdog tesztelés alatt legyen kikapcsolva, mert kívülről újraindítva megkerülheti a programon belüli próbálkozási korlátot.

Az L2TP/IPsec IKEv1 és MS-CHAPv2 régi protokollok; ez a csomag a meglévő hozzáférés kompatibilitását célozza, nem állítja, hogy ez a legkorszerűbb VPN-választás. Nem adtunk hozzá automatikus gyengítésre váltó algoritmuslistát.

## Ellátási lánc

A veepin forrás rögzített Git-commitból épül, az addon csak a nyilvános L2TP API-t használja. A Go-modulokat az upstream `go.mod`/`go.sum` alapján tölti le. A Go és Alpine alapképek verziócímkések, nem digestre rögzítettek; a teljes build bitazonos reprodukálhatósága nem igazolt. Internetelérés kell a fordításhoz. A GitHub Actions csak olvasási jogosultságot kér, képet nem publikál és VPN-re nem jelentkezik be.
