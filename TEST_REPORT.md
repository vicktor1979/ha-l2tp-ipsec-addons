# Tesztjelentés – 0.1.0

Ellenőrzés dátuma: 2026. szeptember 11.  
Környezet: Linux, Python 3.13.5; nem Home Assistant OS.

## Sikeresen végrehajtott ellenőrzések

- `python -m unittest discover -s tests -v`: **28 teszt, 28 sikeres**.
- Mindkét Python-fájl szintaktikai ellenőrzése.
- Öt YAML-fájl beolvasása; az addon alapbeállításai és sémája azonos mezőket tartalmaznak.
- A magyar és az angol konfigurációfordítások mezőnevei egyeznek a sémával.
- Diagnosztikai alapindítás, kikapcsolt host-hálózat és nem publikált LAN-port ellenőrzése.
- A konfiguráció alapértékeiben nincs valódi szervercím, felhasználónév, jelszó vagy PSK.

A 28 teszt a bemenetek ellenőrzését, hitelesítési módokat, PPP-idézőjelezést,
PSK-kódolást, konfigurációgenerálást, titkos fájlok jogosultságát, symlinkek
elutasítását, naplókitakarást, SA-állapot felismerését és a továbbító kód
kétirányú bináris adatátadását vizsgálja. Az adatátadási próba helyi Python
socketpárokat használ, nem VPN-t vagy valódi C6 adaptert.

A tűzfalszabályoknál a parancsok **összeállítása** lett ellenőrizve; ez nem
bizonyítja azok futó Linux-kernelen való érvényesülését. A titokkitakarási
tesztek sem jelentenek teljes, független biztonsági auditot.

## Ebben a környezetben nem végrehajtott ellenőrzések

- Alpine-csomagok tényleges telepítése és Docker-kép buildje.
- A mellékelt GitHub Actions workflow futtatása.
- Telepítés és indítás Home Assistant Supervisor / HA OS alatt.
- A felhasználó HA OS kernelének PPP-, L2TP-, XFRM- és policy-támogatása.
- Valódi IPsec-/L2TP-hitelesítés a Giganet VPN-szerverén.
- HA addon-DNS, ebusd → átjáró → C6 teljes adatút és eBUS-kommunikáció.
- VPN-megszakadás, újracsatlakozás, IPsec-újrakulcsolás és hosszú távú üzem.
- A hálózati tiltások, kernelmodulok és leállítási eljárás helyszíni működése.

A Docker parancs és a felhasználó VPN-végpontja ebben a tesztkörnyezetben nem
állt rendelkezésre. **A csomag kísérleti prototípus, nem igazoltan működő kiadás.**

## Javasolt helyszíni ellenőrzési sorrend

Először HA-mentés és a `SECURITY.md` átolvasása. Feltöltés után a GitHub Actions
build megmutathatja a csomagtelepítési vagy konténerépítési hibákat. Ezután
következhet az addon telepítése és a `diagnostics_only: true` indítás.
Csak sikeres `DIAGNOSTICS_OK` után érdemes valódi VPN-adatokkal próbálkozni.
Az eBUS elérést kezdetben olvasással teszteld; az üzemi fűtési vezérlést
ne tedd függővé ettől az első kísérleti kiadástól.
