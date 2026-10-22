# PromptCloak

Makaledeki yerel maskeleme ve tersine maskeleme katmanının yeniden üretim paketi.

Makale: *Yapay Zekâ Destekli Kod Üretiminde Hassas Veri Sızıntısının Önlenmesi: Yerel Maskeleme ve Tersine Maskeleme Tabanlı Bir Güvenlik Katmanı* (Efendioğlu, Emekli).

Sürüm: `1.0.0-paper` · Python 3.11+ · Veri DOI: [10.57967/hf/9800](https://doi.org/10.57967/hf/9800)

## Bu pakette ne var

- Yerel regex motoru: `patterns.py`, `masking.py`
- Masaüstü arayüz (PromptCloak maskeleme ekranı): yapıştır, özel regex, bulgular, maskele, tersine maskele, fail-closed
- Makaledeki değerlendirme betikleri ve `reproduce.sh`

## Gereksinimler

- Python 3.11+
- Arayüz için: `pip3 install -r requirements.txt` (`pywebview`)
- Tablo 11 için isteğe bağlı: `brew install gitleaks trufflehog`

## Arayüzü çalıştırma

```bash
cd promptcloak-paper
pip3 install -r requirements.txt
python3 desktop_app.py
```

`python3 app_ui.py` aynı pencereyi açar. Arayüz varsayılanı İngilizcedir; **Ayarlar**’dan Türkçe seçilir.

1. Kodu yapıştırın veya **Yerleşik örnek** / **Parçalı anahtar örneği**.
2. İsterseniz **Özel kurallar (regex)** ekleyin. Parçalı örnek, yerleşik kataloğun kaçırdığı bölünmüş sır için `split_sk` kuralını ekler (makaledeki ~%14,5 sızıntı kesiti).
3. **Maskele** — sağ kutu maskeli metindir; altta bulgular görünür.
4. Fail-closed uyarısı çıkarsa metni modele taşımayın.
5. Maskeli metni kendi LLM’inize yapıştırın. Yanıtı sağ kutuya koyup **Tersine Maskele**.
6. Sol alttan **Ayarlar**: görünüm (koyu / açık) ve dil (TR / EN).

İki kez `python3 desktop_app.py` = iki oturum; eşleme tabloları karışmaz.

## Veri

Hizalı N=300 ve bölünmüş-sır JSON’ları GitHub’a konmaz (sentetik anahtar biçimi push korumasını tetikler). Bir kez indirin:

```bash
python3 fetch_data.py
```

Bu komut DOI 10.57967/hf/9800 dosyalarını `data/` altına alır ve tuzak setini `generate_hard_negatives_n300.py` ile üretir. Temiz küme (`data/extensions/clean_code_snippets_n300.json`) zaten repodadır.

## Deneyleri tekrarlama

```bash
chmod +x reproduce.sh
./reproduce.sh
```

`reproduce.sh` önce `fetch_data.py` çalıştırır, sonra betikleri sırayla koşar. Çıktı: `out/`.

| Betik | Makale | Beklenen |
|-------|--------|----------|
| `python3 evaluate.py` | N=300 hizalı, Tablo 5/12 | P=R=F1=1,00; sızıntı 0; round-trip 300/300 |
| `python3 evaluate_clean.py` | Temiz N=300 | 0/300 FP |
| `python3 evaluate_hard_negatives.py` | Zor negatif N=300 | 20/300 FP (%6,7), hepsi `docs_literal` |
| `python3 evaluate_split_custom.py` | Bölünmüş sır | yerleşik sızıntı ~%14,5 |
| `python3 evaluate_concurrent_sessions.py` | Eşzamanlı 300 çift | karışma 0 |
| `python3 compare_scanners_n300.py` | Tablo 11 | Gitleaks F1≈0,38; TruffleHog F1≈0,27 |

Hizalı setteki 1,00 genelleme değildir.

Canlı GPT-4o / GPT-4o-mini yer tutucu sayıları makalede raporlanır; bu paket API çağrısı yapmaz.

## Dosyalar

```
desktop_app.py                 masaüstü pencere
app_ui.py                      aynı pencereyi açar
web/index.html                 arayüz
web_app.py                     yerel mask / unmask
patterns.py                    regex kataloğu
masking.py                     mask / unmask / fallback
fetch_data.py                  N=300 ve split indirme
generate_hard_negatives_n300.py  tuzak seti
evaluate*.py                   makale kesitleri
compare_scanners_n300.py       Tablo 11
reproduce.sh                   tüm kesitler
data/                          veri ve uzantılar
out/                           beklenen özet raporlar
ALGORITHM.md                   sözde kod
VERSION                        1.0.0-paper
```

Gitleaks 8.30.1 ve TruffleHog 3.99.2 makaledeki sürümlerdir; daha yeni sürüm sayıları biraz kaydırabilir.

## Kaynakça

Veri seti: Efendioğlu NN. Synthetic Sensitive Data in Source Code (N=300). Hugging Face Datasets, 2026. DOI: 10.57967/hf/9800.

Kod: Efendioğlu NN., Emekli HB. PromptCloak, 1.0.0-paper. https://github.com/nisaefendioglu/promptcloak-paper

---

# English

Reproduction package for the article’s local mask / unmask layer.

Paper: *Preventing Sensitive Data Leakage in AI-Assisted Code Generation: A Security Layer Based on Local Masking and Reverse Masking* (Efendioğlu, Emekli).

Version: `1.0.0-paper` · Python 3.11+ · Data DOI: [10.57967/hf/9800](https://doi.org/10.57967/hf/9800)

## What this package contains

- Local regex engine: `patterns.py`, `masking.py`
- Desktop UI (PromptCloak masking screen): paste, custom regex, findings, mask, unmask, fail-closed
- Evaluation scripts from the paper and `reproduce.sh`

## Requirements

- Python 3.11+
- For the UI: `pip3 install -r requirements.txt` (`pywebview`)
- Optional for Table 11: `brew install gitleaks trufflehog`

## Run the UI

```bash
cd promptcloak-paper
pip3 install -r requirements.txt
python3 desktop_app.py
```

`python3 app_ui.py` opens the same window. The UI defaults to English; switch to Turkish in **Settings**.

1. Paste code, or use **Built-in sample** / **Split key sample**.
2. Add **Custom rules (regex)** if needed. The split sample adds a `split_sk` rule for concatenated keys that the built-in catalog misses (the paper’s ~14.5% leak slice).
3. **Mask** — the right pane is the masked text; findings appear below.
4. If the fail-closed warning appears, do not send the text to a model.
5. Paste the masked text into your own LLM. Put the reply in the right pane and **Unmask**.
6. Bottom-left **Settings**: appearance (dark / light) and language (TR / EN).

Two `python3 desktop_app.py` processes are two sessions; mapping tables stay isolated.

## Data

The aligned N=300 and split-secret JSON files are not in Git (synthetic key shapes trip push protection). Download once:

```bash
python3 fetch_data.py
```

This fetches DOI 10.57967/hf/9800 into `data/` and generates the trap set with `generate_hard_negatives_n300.py`. The clean set (`data/extensions/clean_code_snippets_n300.json`) is already in the repo.

## Reproduce the experiments

```bash
chmod +x reproduce.sh
./reproduce.sh
```

`reproduce.sh` runs `fetch_data.py` first, then the scripts in order. Output: `out/`.

| Script | Paper | Expected |
|--------|--------|----------|
| `python3 evaluate.py` | Aligned N=300, Tables 5/12 | P=R=F1=1.00; leak 0; round-trip 300/300 |
| `python3 evaluate_clean.py` | Clean N=300 | 0/300 FP |
| `python3 evaluate_hard_negatives.py` | Hard-negative N=300 | 20/300 FP (6.7%), all `docs_literal` |
| `python3 evaluate_split_custom.py` | Split secret | built-in leak ~14.5% |
| `python3 evaluate_concurrent_sessions.py` | Concurrent 300 pairs | mix 0 |
| `python3 compare_scanners_n300.py` | Table 11 | Gitleaks F1≈0.38; TruffleHog F1≈0.27 |

The 1.00 score on the aligned set is not generalization.

Live GPT-4o / GPT-4o-mini placeholder numbers are reported in the paper; this package does not call an API.

## Files

```
desktop_app.py                 desktop window
app_ui.py                      same window
web/index.html                 UI
web_app.py                     local mask / unmask
patterns.py                    regex catalog
masking.py                     mask / unmask / fallback
fetch_data.py                  N=300 and split download
generate_hard_negatives_n300.py  trap set
evaluate*.py                   paper slices
compare_scanners_n300.py       Table 11
reproduce.sh                   all slices
data/                          data and extensions
out/                           expected summary reports
ALGORITHM.md                   pseudocode
VERSION                        1.0.0-paper
```

Gitleaks 8.30.1 and TruffleHog 3.99.2 are the versions in the paper; newer releases may shift the numbers slightly.

## Cite

Dataset: Efendioğlu NN. Synthetic Sensitive Data in Source Code (N=300). Hugging Face Datasets, 2026. DOI: 10.57967/hf/9800.

Code: Efendioğlu NN., Emekli HB. PromptCloak, 1.0.0-paper. https://github.com/nisaefendioglu/promptcloak-paper
