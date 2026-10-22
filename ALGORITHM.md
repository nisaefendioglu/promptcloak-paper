# Algoritma / Algorithm (makale §2.4–2.6)

1. Aday regex’ler `patterns.py` içindeki `RULES` listesinde **öncelik sırasıyla** uygulanır (spesifik / uzun kural önce).
2. Örtüşen eşleşmede soldaki ve daha uzun span seçilir (`find_matches`).
3. Her değer oturum içinde tek simge alır: `t_v = [LOCAL_MASKED_<TÜR>_<tag>_<n>]`.
4. Eşleme tablosu `T` yalnızca süreç belleğindedir; diske yazılmaz.
5. Fail-closed: maskeli `X′` içinde hâlâ düz sır varsa modele gönderilmez (UI uyarı verir).
6. Unmask: yanıt `Y` içinde bilinen simgeler `T` ile geri yazılır. Bilinmeyen simge bırakılır.
7. Fallback (makale canlı kesiti): simge `Y`’de yoksa değer yine `T`’den, satır/atama bağlamıyla yazılır (`unmask_with_fallback` in `masking.py`).

Tekrarlanan aynı sır → aynı simge. İki oturum = iki `MaskingEngine` (farklı `_tag`).
