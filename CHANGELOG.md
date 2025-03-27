# CHANGELOG

## [27.3.2025] - Dátum vydania
### Pridané
- Implementované základné TCP SYN a UDP skenovanie pre IPv4 a IPv6.
- Podpora pre raw sockety na nízkoúrovňovú manipuláciu s paketmi.
- Použitie knižnice pcap na získanie sieťových rozhraní.
- Paralelizované odosielanie a prijímanie paketov pomocou vlákien.
- Pridané testovacie prípady na overenie správnosti detekcie otvorených a zatvorených portov.
- Dokumentácia projektu v `README.md`.

## Známé obmedzenia
- Niektoré operačné systémy vyžadujú špeciálne oprávnenia na prácu s raw socketmi (spustenie so `sudo`).
- IPv6 podpora môže byť obmedzená v niektorých sieťových konfiguráciách.
- Ďalšie obmedzenia nie sú známe.


