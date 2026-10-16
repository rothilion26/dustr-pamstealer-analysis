# "Dustr" kampanyası: Türkçe özet

**Tarih:** 2026-10-17 · **Yöntem:** yalnızca statik analiz. Hiçbir aşama çalıştırılmadı, C2 sunucusuna bağlanılmadı.

## Ne oldu?

X'te "Dustr" adlı sahte bir Mac temizleme uygulamasının reklamı yayınlandı. Reklamın götürdüğü `dustr[.]app` sitesi, ziyaretçiden **Terminal'e bir komut yapıştırmasını** istiyor ("ClickFix" tekniği). Komut, `keychainagent[.]pro` adresinden gizlenmiş bir JavaScript (JXA) yükleyiciyi indirip doğrudan bellekte çalıştırıyor.

Zararlı yazılım, Jamf Threat Labs'ın **PamStealer** adını verdiği macOS bilgi hırsızı ailesinin yeni bir varyantı. Tarayıcı parolalarını ve çerezlerini, Keychain kayıtlarını ve kripto cüzdan verilerini hedefliyor.

## Öne çıkan bulgular

- **Ortama bağlı anahtar:** 1. aşama, makinede 8 kontrol yapıyor: sanal makine, SIP, debugger, dil, klavye ve saat dilimi. Şifre çözme anahtarını bu kontrollerin sonuçlarından üretiyor. Sanal makinede, debugger altında ya da BDT ülkelerine ayarlı bir Mac'te anahtar yanlış çıkıyor ve zararlı hiçbir şey yapmıyor. **Türkiye bu hariç tutma listesinde yok.**
- **Kurulum:** 3. aşama, Rust ile yazılmış bir program. Kendini `~/Library/Caches/com.apple.finder/Finder.app` adıyla gizliyor.
- **C2 adresi çözüldü:** Programın içindeki şifreli yapılandırma, hiçbir şey çalıştırılmadan statik olarak çözüldü. Ortaya çıkan değerler şunlar:
  - **`hxxps://gatewaysync[.]pro/api/sync`** (büyük ihtimalle komuta-kontrol sunucusu)
  - `detox` kampanya etiketi
  - bir Ethereum kontratı adresi
  - bir anahtar
  Bu adres, aynı ailenin daha önce yayımlanmış analizlerinde bulunamamıştı.
- **Gömülü Keychain aracı (`kh_tmp`):** Kullanıcıdan Keychain erişim izni istiyor; "Reddet"e basılırsa en fazla 10 kez tekrar soruyor.
- **Altyapı:** Dağıtım sunucusu ile C2 sunucusunun sertifikaları 4 saniye arayla alınmış. Bu, ikisinin aynı operatöre ait olduğunu gösteriyor.

## Kendini korumak için

- Bir web sitesi senden **Terminal'e komut yapıştırmanı** istiyorsa yapma. Meşru yazılımlar böyle kurulmaz.
- Şu klasörün varlığını kontrol et: `~/Library/Caches/com.apple.finder/Finder.app`. Gerçek Finder yalnızca `/System/Library/CoreServices` altında bulunur.
- Ayarlar → Genel → Giriş Öğeleri altında tanımadığın bir "Finder" kaydı var mı, bak.

Ayrıntılı teknik rapor (İngilizce): [writeup.md](writeup.md)
