# 0.2.1 helyi ellenőrzési jelentés – 2026-09-14

## Ténylegesen elvégzett vizsgálatok

* `python -m unittest discover -s tests -v`: **76 sikeres teszt**.
  Ebből 42 a korábbi beállítás-, jogosultság-, route-, napló- és helyi
  TCP-relay regressziós teszt; 34 új teszt a módokról, CIDR/port-határokról,
  VPN előtti kereséstilalomról, TUN-kötésről és IKE-fejlécfeldolgozásról.
* `go test -v config.go config_test.go`: **2 sikeres standard-library teszt**.
  Ez nem a teljes veepin motor fordítása vagy protokolltesztje.
* Külön valódi, loopback TCP-próba a kereső `probe_tcp` függvényével:
  a socket `lo` interfészhez és 127.0.0.1 forráscímhez kötve elérte a helyi
  teszt-listenert (`REAL_LOOPBACK_BOUND_PROBE_OK`). Nem külső célpont.
* Python szintaxisellenőrzés, YAML-fájlok beolvasása, manifest/fordítási fájlok
  és fordítási workflow ellenőrzése. A végeredmény a kiadási csomagban van.

## Korlátok és el nem végzett vizsgálatok

* Valódi AF_PACKET IKE-megfigyelés: a helyi környezet jogosultsági korlátja
  miatt nem futott (`Operation not permitted`). A parser és a korreláció
  szintetikus csomagokkal tesztelt. A HA-n NET_RAW és AppArmor mellett
  külön ellenőrizni kell, hogy az observer elindul-e.
* Nincs teljes Docker-build: itt nincs működő Docker-környezet és az
  upstream függőségek konténeres letöltése sem állt rendelkezésre.
* Nincs valódi 0.2.1 HA-installáció, TUN-routolás vagy IPsec-tunnel teszt.
* Nincs Giganet VPN-bejelentkezés, távoli hálózatpásztázás vagy C6-teszt.
* Az aarch64 támogatás deklarált, de build/runtime ebben a körben nem tesztelt.
* Nincs független kriptográfiai vagy biztonsági audit.

A 0.2.0-ról a felhasználó által bemásolt napló igazolja a saját rendszerén
az akkori TUN- és motorindítást, de ez nem tekinthető a 0.2.1 új funkcióinak
helyi igazolásának. A tényleges VPN ott IKE-időtúllépéssel állt meg.

## Következő helyszíni ellenőrzés

1. GitHub Actions: teljes Docker-build és helyi TUN-előellenőrzés, titkok nélkül.
2. HA-n 0.2.1, `diagnostics_only: false`, `connection_mode: vpn_test`,
   `ike_trace: true`, `max_retries: 1`; Watchdog és automatikus indítás kikapcsolva.
3. A kapcsolat és a pontos távoli CIDR igazolása után egyszeri `discover` mód.

A kiadás diagnosztikai és keresési bővítés; az upstream VPN-protokollmotor
változatlan. A jelenlegi IKE-hiba javítását nem állítjuk.
