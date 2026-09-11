# Ellenőrzési jelentés – 0.2.0

Dátum: 2026-09-11. A jelentés a csomag létrehozásakor ténylegesen végzett ellenőrzéseket különíti el a tervezett ellenőrzésektől.

## Lefutott és sikeres

| Ellenőrzés | Eredmény | Mit fed le? |
|---|---|---|
| `python3 -m unittest discover -s tests -v` | **42 teszt sikeres** | Konfiguráció, titokmaszkolás, útvonalparancsok, TUN-hibaszövegek szimulált rendszerhívásokkal, motoresemények, VPN-interfészhez kötés sorrendje és tiltott fallback, TCP-relé, manifest. |
| `go test -v config.go config_test.go` a helper mappában | **2 tesztfüggvény sikeres**, az egyik 6 hibás bemenetet vizsgál | Csak a Go standard library alapú JSON-/belépésiadat-feldolgozó. Nem importálja és nem fordítja a veepin motort. |
| `python3 -m py_compile` | Sikeres | Python-szintaxis. |
| `gofmt` | Sikeres | A Go-források formázása/szintaktikai feldolgozása; nem típusellenőrzött teljes motor-build. |
| YAML beolvasás és opció-/fordításikulcs-egyezés | Sikeres | Manifest, repository, magyar/angol fordítások, workflow szerkezeti vizsgálata. Nem teljes Supervisor-validáció. |
| Csomagstruktúra | Sikeres | Gyökérszintű repository.yaml, változatlan slug, 0.2.0 verzió, új helper mappa, tesztek, workflow; nincs külső mappaszint. |

A tesztkörnyezet: Python 3.13.5, Go 1.23.2, Linux amd64. A Go 1.23.2 csak az önálló, standard library alapú bemenetellenőrzési tesztet futtatta. A teljes motor a Dockerfile-ban Go 1.27.0 fordítót használ.

**A négy Python RelayIntegrationTests-teszt valódi helyi TCP/socketpair kapcsolatot használ. Nem egy valódi C6-ot, nem VPN-szervert és nem TUN-t tesztel.** A tesztfuttatás naplójában megjelenő `C6_TCP_CONNECTED` és más státuszok tesztkörnyezetből származnak, nem tényleges VPN/adapterelérés bizonyítékai.

## Nem futott le / nem igazolt

- A teljes Go-illesztő összefordítása a rögzített veepin-függőséggel.
- A Docker-image felépítése és a csomagletöltések sikeressége.
- GitHub Actions futás a felhasználó repositoryjában.
- Valódi `/dev/net/tun`, capability- és AppArmor-ellenőrzés a felhasználó HA OS-én.
- A Home Assistant 0.1.0 → 0.2.0 frissítési/migrációs folyamata.
- amd64 vagy aarch64 Home Assistant runtime; ARM-build.
- Giganet IKEv1/ESP ajánlategyezés, NAT-T, L2TP/MS-CHAPv2 hitelesítés.
- Valódi C6 TCP-port, ebusd enhanced adatfolyam, hosszú távú szakadás/újracsatlakozás.
- Biztonsági audit vagy az upstream kriptográfiai megvalósításának független ellenőrzése.

Ebben a munkakörnyezetben nincs Docker futtató; az upstream teljes letöltése és a Go-függőségek fordítása nem volt elvégezhető. A nyilvános upstream API-t forrásszinten átnéztük, de ez nem helyettesíti a rögzített kiadással történő teljes buildet.

## Következő, tényleges ellenőrzési sorrend

1. Feltöltés után GitHub Actions: teljes amd64 Docker-build és jelszó nélküli TUN-próba a CI-gépen. Az itt sikeres TUN-próba nem igazolja a HA AppArmor-profilját.
2. A felhasználó HA-ján 0.2.0, `diagnostics_only: true`, VPN-adatok nélkül.
3. Sikeres helyi diagnosztika után külön Giganet VPN-bejelentkezés, helyben megadott titkokkal.
4. `VPN_UP`/`PROXY_READY` után az ebusd egyetlen C6-kapcsolatának ellenőrzése.

A sikeres offline tesztek alapján **nem állítjuk**, hogy a csomag már működőképes a felhasználó hálózatában. Ez a kipróbálásra előkészített kísérleti megvalósítás.
