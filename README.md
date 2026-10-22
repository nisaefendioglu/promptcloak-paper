# PromptCloak

[TR](#tr) · [EN](#en)

<h2 id="tr">Türkçe</h2>

Makaledeki yerel maskeleme / tersine maskeleme katmanını **hiçbir API anahtarı olmadan** deneyebilirsiniz.

Makale: *Yapay Zekâ Destekli Kod Üretiminde Hassas Veri Sızıntısının Önlenmesi: Yerel Maskeleme ve Tersine Maskeleme Tabanlı Bir Güvenlik Katmanı* (Efendioğlu, Emekli). Sürüm `1.0.0-paper`.

- Kod: https://github.com/nisaefendioglu/promptcloak-paper
- Veri: https://huggingface.co/datasets/nisaefendioglu/synthetic-sensitive-data-in-source-code-n300 (DOI [10.57967/hf/9800](https://doi.org/10.57967/hf/9800))

Makalede yeniden üretim kısa tutulur (Bölüm 2.1 / 2.6 ve Kaynakça): repo, HF adresi, `python3 desktop_app.py`, `python3 fetch_data.py && ./reproduce.sh`. Adım adım komutlar bu README’dedir.

## 1. İlk kurulum (bir kez)

Bilgisayarınızda Python 3.11 veya üzeri olsun (`python3 --version`).

```bash
git clone https://github.com/nisaefendioglu/promptcloak-paper.git
cd promptcloak-paper
python3 -m pip install -r requirements.txt
```

`requirements.txt` yalnızca arayüz için `pywebview` kurar. Motor (`masking.py`) ek paket istemez.

## 2. Ne yapmak istiyorsunuz?

### Pencereyi açıp maskeleme denemek

```bash
python3 desktop_app.py
```

`python3 app_ui.py` aynı penceredir. Dil varsayılanı İngilizce; sol alt **Settings → Türkçe**.

1. Ortaya kod yapıştırın **veya** **Yerleşik örnek** / **Parçalı anahtar örneği**’ne basın.
2. **Maskele** — sağ kutu maskeli metin; altta bulgular (yalnızca maskeden sonra).
3. Fail-closed uyarısı varsa metni bir modele **göndermeyin**.
4. Maskeli metni kendi LLM’inize yapıştırın. Yanıtı sağa koyup **Tersine Maskele**.
5. Parçalı örnek, yerleşik kataloğun kaçırdığı bölünmüş sır için `split_sk` özel kuralını ekler (makaledeki ~%14,5 sızıntı). İsterseniz **Özel kurallar (regex)** ile kendi kuralınızı yazın.

İki kez `python3 desktop_app.py` = iki oturum; eşleme tabloları karışmaz.

### Yalnızca makale tablolarını yeniden üretmek

İnternet gerekir (Hugging Face’ten veri iner). Gitleaks/TruffleHog **yoksa** Tablo 11 tarayıcı satırları atlanır, diğerleri yine çalışır.

```bash
python3 fetch_data.py
chmod +x reproduce.sh
./reproduce.sh
```

Raporlar: `out/`. Beklenen sayılar aşağıda.

### Veriyi indirmek (deney koşmadan)

```bash
python3 fetch_data.py
```

JSON’lar GitHub’da yoktur (sentetik anahtar biçimi push korumasını tetikler). Hepsi tek HF paketindedir:

| Küme | HF dosya / Viewer | Makale |
|------|-------------------|--------|
| Hizalı N=300 | `synthetic_sensitive_data_in_source_code_n300.json` · `sensitive_n300` | Tablo 5/12 |
| Temiz N=300 | `extensions/clean_code_snippets_n300.json` · `clean_n300` | 0/300 FP |
| Bölünmüş sır | `extensions/split_pattern_custom_n300.json` · `split_pattern_n300` | ~%14,5 sızıntı |
| Tuzak / zor negatif | `extensions/hard_negatives_n300.json` · `hard_negatives_n300` | 20/300 FP |

Tuzak dosyası inmezse: `python3 generate_hard_negatives_n300.py`. Temiz küme zaten repodadır.

### Tek bir tabloyu / kesiti koşmak

Önce bir kez `python3 fetch_data.py`.

| İstediğiniz | Komut | Beklenen |
|-------------|--------|----------|
| Hizalı N=300 P/R/F1, sızıntı, round-trip (Tablo 5/12) | `python3 evaluate.py` | P=R=F1=1,00; sızıntı 0; RT 300/300 |
| Temiz küme yanlış alarm | `python3 evaluate_clean.py` | 0/300 FP |
| Zor negatif / tuzak | `python3 evaluate_hard_negatives.py` | 20/300 FP (%6,7), hepsi `docs_literal` |
| Bölünmüş sır sızıntısı | `python3 evaluate_split_custom.py` | yerleşik ~%14,5 |
| Eşzamanlı iki oturum | `python3 evaluate_concurrent_sessions.py` | karışma 0 |
| Konum F1 ve kısmi sızıntı (Tablo 13) | `python3 evaluate_position_partial.py` | konum F1≈0,99; kısmi 0 |
| Uzunluk × yoğunluk gecikme (Tablo 14) | `python3 evaluate_latency_sweep.py` | p50 ms; 32 bin karakterde ~13–15 ms |
| Naif regex + Gitleaks + TruffleHog (Tablo 11) | `python3 compare_scanners_n300.py` | naif F1≈0,62; Gitleaks ≈0,38; TruffleHog ≈0,27 |

Hizalı setteki 1,00 genelleme değildir.

Tablo 11 tarayıcıları için (isteğe bağlı, macOS):

```bash
brew install gitleaks trufflehog
```

Makaledeki sürümler: Gitleaks **8.30.1**, TruffleHog **3.99.2**. Daha yeni sürüm sayıları biraz kayabilir.

### Canlı GPT-4o / GPT-4o-mini yer tutucu sayıları

Makalede raporlanır. Bu paket **API çağırmaz**; anahtar gerekmez.

### Sözde kod / algoritma

`ALGORITHM.md`

## Dosyalar

```
desktop_app.py / app_ui.py     masaüstü pencere
web/index.html                 arayüz
web_app.py                     yerel mask / unmask
patterns.py                    regex kataloğu
masking.py                     mask / unmask / fallback
fetch_data.py                  HF indirme
generate_hard_negatives_n300.py  tuzak seti (yedek)
evaluate*.py                   makale kesitleri
compare_scanners_n300.py       Tablo 11
reproduce.sh                   tüm kesitler
data/                          inen JSON’lar
out/                           raporlar
```

## Kaynakça

Veri: Efendioğlu NN. Synthetic Sensitive Data in Source Code (N=300). Hugging Face Datasets, 2026. DOI: 10.57967/hf/9800.

Kod: Efendioğlu NN., Emekli HB. PromptCloak, 1.0.0-paper. https://github.com/nisaefendioglu/promptcloak-paper

---

<h1 id="en">English</h1>

[TR](#tr) · [EN](#en)

You can try the paper’s local mask / unmask layer **without any API key**.

Paper: *Preventing Sensitive Data Leakage in AI-Assisted Code Generation: A Security Layer Based on Local Masking and Reverse Masking* (Efendioğlu, Emekli). Version `1.0.0-paper`.

- Code: https://github.com/nisaefendioglu/promptcloak-paper
- Data: https://huggingface.co/datasets/nisaefendioglu/synthetic-sensitive-data-in-source-code-n300 (DOI [10.57967/hf/9800](https://doi.org/10.57967/hf/9800))

The article keeps reproducibility short (§2.1 / 2.6 and the bibliography): repo, HF URL, `python3 desktop_app.py`, `python3 fetch_data.py && ./reproduce.sh`. Step-by-step commands live here.

## 1. One-time setup

Python 3.11+ (`python3 --version`).

```bash
git clone https://github.com/nisaefendioglu/promptcloak-paper.git
cd promptcloak-paper
python3 -m pip install -r requirements.txt
```

`requirements.txt` installs `pywebview` for the window. The engine (`masking.py`) needs no extra packages.

## 2. What do you want to do?

### Open the window and try masking

```bash
python3 desktop_app.py
```

`python3 app_ui.py` is the same window. Default language is English; **Settings** (bottom left) switches to Turkish.

1. Paste code, or click **Built-in sample** / **Split key sample**.
2. **Mask** — right pane is the masked text; findings appear only after a mask.
3. If the fail-closed warning appears, **do not** send the text to a model.
4. Paste the masked text into your own LLM. Put the reply on the right and **Unmask**.
5. The split sample adds a `split_sk` custom rule for concatenated keys the built-in catalog misses (the paper’s ~14.5% leak). You can also type your own rule under **Custom rules (regex)**.

Two `python3 desktop_app.py` processes are two sessions; mapping tables stay isolated.

### Reproduce every paper table

Needs the network (downloads from Hugging Face). Without Gitleaks/TruffleHog, Table 11 scanner rows are skipped; the rest still runs.

```bash
python3 fetch_data.py
chmod +x reproduce.sh
./reproduce.sh
```

Reports: `out/`. Expected numbers are below.

### Download data only

```bash
python3 fetch_data.py
```

JSON files are not in Git (synthetic key shapes trip push protection). All splits are in one HF dataset:

| Split | HF file / Viewer | Paper |
|-------|------------------|--------|
| Aligned N=300 | `synthetic_sensitive_data_in_source_code_n300.json` · `sensitive_n300` | Tables 5/12 |
| Clean N=300 | `extensions/clean_code_snippets_n300.json` · `clean_n300` | 0/300 FP |
| Split secret | `extensions/split_pattern_custom_n300.json` · `split_pattern_n300` | ~14.5% leak |
| Hard negatives / traps | `extensions/hard_negatives_n300.json` · `hard_negatives_n300` | 20/300 FP |

If the trap file is missing: `python3 generate_hard_negatives_n300.py`. The clean set is already in the repo.

### Run one table / slice

Download once with `python3 fetch_data.py`.

| Goal | Command | Expected |
|------|---------|----------|
| Aligned N=300 P/R/F1, leak, round-trip (Tables 5/12) | `python3 evaluate.py` | P=R=F1=1.00; leak 0; RT 300/300 |
| Clean-set false alarms | `python3 evaluate_clean.py` | 0/300 FP |
| Hard negatives / traps | `python3 evaluate_hard_negatives.py` | 20/300 FP (6.7%), all `docs_literal` |
| Split-secret leak | `python3 evaluate_split_custom.py` | built-in ~14.5% |
| Two concurrent sessions | `python3 evaluate_concurrent_sessions.py` | mix 0 |
| Span F1 and partial leak (Table 13) | `python3 evaluate_position_partial.py` | span F1≈0.99; partial 0 |
| Length × density latency (Table 14) | `python3 evaluate_latency_sweep.py` | p50 ms; ~13–15 ms at 32k chars |
| Naive regex + Gitleaks + TruffleHog (Table 11) | `python3 compare_scanners_n300.py` | naive F1≈0.62; Gitleaks ≈0.38; TruffleHog ≈0.27 |

The 1.00 on the aligned set is not generalization.

Optional scanners for Table 11 (macOS):

```bash
brew install gitleaks trufflehog
```

Paper versions: Gitleaks **8.30.1**, TruffleHog **3.99.2**. Newer releases may shift the scores slightly.

### Live GPT-4o / GPT-4o-mini placeholder numbers

Reported in the paper. This package **does not call an API**; no key is required.

### Pseudocode / algorithm

`ALGORITHM.md`

## Files

```
desktop_app.py / app_ui.py     desktop window
web/index.html                 UI
web_app.py                     local mask / unmask
patterns.py                    regex catalog
masking.py                     mask / unmask / fallback
fetch_data.py                  HF download
generate_hard_negatives_n300.py  trap set (fallback)
evaluate*.py                   paper slices
compare_scanners_n300.py       Table 11
reproduce.sh                   all slices
data/                          downloaded JSON
out/                           reports
```

## Cite

Dataset: Efendioğlu NN. Synthetic Sensitive Data in Source Code (N=300). Hugging Face Datasets, 2026. DOI: 10.57967/hf/9800.

Code: Efendioğlu NN., Emekli HB. PromptCloak, 1.0.0-paper. https://github.com/nisaefendioglu/promptcloak-paper
