# 変更の履歴 (kompira-ca-check.py)

## 未リリース

- 2.0 系で pip が 24.1 より前のとき、`REQUESTS_CA_BUNDLE` (または `CURL_CA_BUNDLE`) があれば、pip の行をそのファイルだけで判定するようにしました。この場合、pip は pip の設定の `cert` よりもそのファイルを優先して使い、pip の中の certifi も使わないためです。2.0.5 以前のイメージ (pip 24.0) を、`REQUESTS_CA_BUNDLE` を設定する Docker Compose の構成で動かしている環境では、告知 4.4 の手順 B の後も、pip の行が `[FAIL]` のままになっていました
- 2.0 系で `SSL_CERT_FILE`・`SSL_CERT_DIR` が OpenSSL の既定と別の場所を指しているときに、git が使う既定のファイルを別の行で確かめるようにしました。git は、これらの環境変数を使わないためです。これまでは、既定のファイルにルートが残っていても、git について `[ OK ]` と表示することがありました

## 1.0.0

- 最初の公開版です
