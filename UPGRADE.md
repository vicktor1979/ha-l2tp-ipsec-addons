# Frissítés 0.1.0-ról 0.2.0-ra

## 1. Mentés és leállítás

Készíts HA-mentést. Állítsd le a régi addont. Az automatikus indítás, az automatikus frissítés és a Watchdog maradjon kikapcsolva a tesztelés idejére. A régi verzióba most ne adj meg új VPN-titkokat.

## 2. A saját GitHub-tároló frissítése

Csomagold ki a ZIP-et. **A teljes kicsomagolt tartalommal írd felül a korábban létrehozott repository fájljait**, az eredeti könyvtárszerkezetben. A ZIP-et ne töltsd fel egyetlen fájlként, és ne legyen körülötte egy további mappaszint.

Kiemelten szükséges fájlok:

```text
repository.yaml
l2tp_ipsec_client/
    config.yaml             # version: 0.2.0
    Dockerfile              # teljesen új fordítási folyamat
    main.py                 # teljesen új vezérlő és proxy
    helper/
        main.go
        config.go
        config_test.go
    translations/
        hu.yaml
        en.yaml
.github/workflows/build.yml
```

A `helper/` mappa új; nélküle a Docker-build nem sikerül. A `.github/` rejtett mappát is töltsd fel, ha az Actions-ellenőrzést használod. A `tests/test_main.py` régi példánya helyett az új kerüljön fel. Nem kell a saját GitHub-felhasználónevedet a forrásba írni.

Az addon `slug` értéke változatlan (`l2tp_ipsec_client`), ezért ugyanabban a repositoryban frissítésként kezelhető. Másik repository hozzáadása külön addonazonosítót hozhat létre.

## 3. Buildellenőrzés és Home Assistant-frissítés

A GitHub **Actions** lapján keresd a `Validate and build experimental C6 gateway` folyamatot. Nem igényel VPN-adatokat. Ha nem indul, ellenőrizd, hogy a `.github/workflows/build.yml` valóban feltöltődött-e és az Actions engedélyezett-e. Ha piros, először a hibás lépés naplóját vizsgáld meg; ne értelmezd VPN-hitelesítési hibának.

A HA bővítmény-/alkalmazásáruházában válaszd a frissítések keresését, majd az addon adatlapján a **Frissítés** lehetőséget. A pontos magyar menünév a HA verziójától függhet. **A telepített verzió a végén 0.2.0 legyen.** Ha csak 0.1.0 látszik, ellenőrizd a GitHubon a `l2tp_ipsec_client/config.yaml` tartalmát és a megfelelő alapértelmezett ágat.

A saját HA-n történő build külső GitHub-, Go-modul- és konténer-/Alpine-források elérését igényli. Egy letöltési/fordítási hiba még nem VPN-probléma.

## 4. Első indítás – csak diagnosztika

A korábbi jogosultságok megváltoztak: nincs teljes hardverhozzáférés, nincs kernelmodul-hozzáférés, az AppArmor vissza van kapcsolva. **Frissítés után kapcsold vissza a Védett módot, és így kezdd a tesztet.** A tényleges HA-változat engedélyezését a naplóval ellenőrizzük; hiba esetén ne adj találomra teljes jogosultságot.

Az addon beállításaiban:

```yaml
diagnostics_only: true
```

Ez konfigurációrészlet, nem a teljes beállításlista. Jelszó nem szükséges. Indítsd az addont, majd a naplóban az alábbi jelzéseket keressük:

```text
L2TP/IPsec C6 átjáró 0.2.0
PPP_KERNEL_NOT_REQUIRED
TUN_OK
ENGINE_OK
DIAGNOSTICS_OK
```

A diagnosztika a saját konténerben rövid életű TUN-t nyit/zár, ellenőrzi az interfészhez kötést, és elindítja a motor `--version` parancsát. Nem tárcsáz VPN-t és nem küld tesztadatot a C6-nak. Ezután az addon várakozva fut tovább; ez szándékos, nem lefagyás.

A `CONFIG_PPP=n` továbbra is igaz lehet a HA OS-re, de ez az új motor számára nem követelmény. Ha még a régi `/dev/ppp`-hibát látod, nem az új `main.py`/Docker-kép fut.

## 5. Csak sikeres diagnosztika után

A [részletes beállítások](l2tp_ipsec_client/DOCS.md) szerint add meg helyben a VPN-adatokat, majd válts `diagnostics_only: false` értékre. Az ebusd beállításait addig ne módosítsd, amíg a `VPN_UP` és a `PROXY_READY` nincs meg.

Az első próbát a már működő amd64 HA-n célszerű végezni. Az `aarch64` manifestengedély bekerült, de az ARM-építés és működés nincs igazolva; a 32 bites ARM nem támogatott.
