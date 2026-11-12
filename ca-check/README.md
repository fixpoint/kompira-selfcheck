# kompira-ca-check.py

認証局 eMudhra (ブランド名 emSign) の中間 CA 証明書の秘密鍵が漏洩した件 (2026 年 10 月) で、信頼から外されたルート証明書を、Kompira が使う CA 証明書のリストがまだ信頼していないかを確かめます。

| ルート証明書 | SHA-256 の指紋 |
|---|---|
| AAA Certificate Services (Comodo AAA Services root) | `d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4` |
| emSign ECC Root CA - G3 | `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b` |

- 設定やファイルを変更しません
- `--online` か `--host` を付けたときだけ、ネットワークに接続します
- Python 3.6 以上の標準ライブラリだけで動きます。Kompira の Python (`/opt/kompira/bin/python`、2.0 系はコンテナの `python`) で実行してください

対処の手順は、Kompira の告知をご覧ください。

## 入手

Release から、スクリプトとハッシュ値のファイル (`SHA256SUMS`) をダウンロードし、ハッシュ値を確かめてから使ってください。

```sh
curl -fsSLO https://github.com/fixpoint/kompira-selfcheck/releases/download/ca-check-v1.0.1/kompira-ca-check.py
curl -fsSLO https://github.com/fixpoint/kompira-selfcheck/releases/download/ca-check-v1.0.1/SHA256SUMS
sha256sum -c SHA256SUMS
```

`kompira-ca-check.py: OK` と表示されれば、ダウンロードしたファイルは壊れていません。ただし、`SHA256SUMS` も同じ場所から取得するため、これだけでは通信経路での差し替えを見抜けません。表示されたハッシュ値が、Kompira の告知に載っている値と一致することも確かめてください。プロキシが必要な環境では、`curl` に `-x http://<プロキシ>:<ポート>` を加えてください。インターネットに接続できないサーバでは、接続できる環境でダウンロードしてハッシュ値を確かめ、サーバに置いてください。

このページには、まだリリースしていない内容が含まれることがあります。お使いの版の説明は、その版のタグ (例: `ca-check-v1.0.0`) の README をご覧ください。

## 使い方

**1.6 系**: Kompira のサーバと、ジョブマネージャだけのサーバのそれぞれで、root で、Kompira の Python (`/opt/kompira/bin/python`) で実行します。ほかの Python で実行すると、Kompira の certifi と pip を確かめられないため、全体の判定は `INCOMPLETE` になります。kompira_sendevt だけのサーバでは、実行する必要はありません (そのサーバで pip を使う場合を除きます)。

```sh
/opt/kompira/bin/python -I kompira-ca-check.py            # ネットワークに接続しない確認だけ
/opt/kompira/bin/python -I kompira-ca-check.py --online   # 確認用サイトへの接続も確かめる
```

`-I` は、作業ディレクトリなどにある Python のファイルを読み込まないようにする指定です。

**2.0 系**: kengine・kompira・jobmngrd の各コンテナで実行します。Docker Swarm では、各ノードで実行してください。Azure Container Instances (ACI) で動かしている構成での実行方法は、確かめていません。

```sh
for c in $(docker ps -q); do
  docker inspect --format '{{.Config.Image}}' $c | grep -q kompira-enterprise || continue
  echo "== $(docker inspect --format '{{.Name}}' $c)"; docker exec -i $c python -I - < kompira-ca-check.py
done
```

Kompira のイメージ (`kompira-enterprise`) から作られたコンテナで実行します。`== <コンテナの名前>` の行で、kengine・kompira・jobmngrd のコンテナがすべて表示されたことを確かめてください。

`--online` を付けるときは、`docker exec -i $c python -I - --online < kompira-ca-check.py` のように、`python -I -` の後に書きます。

**プロキシが必要な環境**で `--online` を使うときは、`https_proxy` を指定してください (`http://` で始まるプロキシの指定に対応しています。`all_proxy` は使いません)。認証が必要なプロキシでは `http://<ユーザ名>:<パスワード>@<プロキシ>:<ポート>` の形で指定します (コマンドの履歴にパスワードが残る点にご注意ください)。ユーザ名やパスワードに `#`・`/`・`?`・`@` を含むときは、`%23`・`%2F`・`%3F`・`%40` と書き換えてください。スクリプトがプロキシの認証情報を表示することはありません。

```sh
https_proxy=http://<プロキシ>:<ポート> /opt/kompira/bin/python -I kompira-ca-check.py --online     # 1.6 系
docker exec -i -e https_proxy=http://<プロキシ>:<ポート> $c python -I - --online < kompira-ca-check.py   # 2.0 系
```

**Kompira のサーバ証明書**: Kompira の Web 画面・REST API (HTTPS) や AMQPS のサーバ証明書を、認証局から発行された証明書に替えている場合は、その発行元も確かめます。1.6 系のサーバでは、Apache と RabbitMQ の設定にある証明書を自動で確かめます (root で実行してください)。2.0 系の Docker のホストなどでは、`--certs-only` を付けて、証明書のファイルかサーバを指定します。

発行元が eMudhra (emSign) のときは `[WARN]` を表示します。影響を受けるのは、信頼から外された 2 つのルート証明書 (emSign ECC Root CA - G3、AAA Certificate Services) に連なる証明書だけです。eMudhra のほかのルート証明書は、引き続き信頼されています。eMudhra の中間 CA には AAA Certificate Services が署名したものもあります (例: EM DV TLS CA - G3B)。スクリプトは、どのルート証明書に連なるかまでは確かめません。認証局に確かめ、2 つのどちらかに連なるなら、ほかの認証局から発行し直してください。

```sh
python3 -I kompira-ca-check.py --certs-only --cert ssl/server.crt              # 証明書のファイル
python3 -I kompira-ca-check.py --certs-only --host kompira.example.com         # サーバが示す証明書 (HTTPS)
python3 -I kompira-ca-check.py --certs-only --host kompira.example.com:5671    # サーバが示す証明書 (AMQPS)
```

## オプション

| オプション | 説明 |
|---|---|
| `--online` | 確認用サイト (漏洩した中間 CA の証明書を使うサイト) に、requests と urllib で接続して確かめます。あわせて、時刻のずれと、TLS を復号するプロキシの有無を確かめます。TLS を復号するプロキシを見つけたとき、時刻が 10 分より大きくずれているとき、確認用サイトの証明書の期限が切れた後は、確認用サイトへの接続は確かめず、全体の判定を `INCOMPLETE` にします |
| `--cert FILE` | Kompira が使うサーバ証明書のファイルの発行元を確かめます (何度でも指定できます) |
| `--host HOST[:PORT]` | サーバが示すサーバ証明書の発行元を確かめます (ポートの既定は 443。AMQPS は 5671。IPv6 のアドレスは `[アドレス]:ポート` と書きます)。プロキシは使いません |
| `--certs-only` | サーバ証明書だけを確かめ、CA 証明書のリストは確かめません (`--online` とは同時に使えません)。Apache や RabbitMQ の設定で見つけた証明書が読めないときは、全体の判定を `INCOMPLETE` にします |
| `--json` | 結果を JSON で出力します |
| `--no-color` | 色を使いません |

## 結果の読み方

最初と最後に、全体の判定を表示します。

```
========================================================================
  RESULT: [FAIL]  ACTION REQUIRED - 2 problem(s) found
========================================================================
```

| 全体の判定 | 意味 | 終了コード |
|---|---|---|
| `[ OK ]  OK` | 信頼から外されたルート証明書を信頼している CA 証明書のリストはありません | 0 |
| `[FAIL]  ACTION REQUIRED` | 対処が必要です。`[FAIL]` の行の `->` に、することを表示します | 1 |
| `[WARN]  CHECK THE WARNINGS` | 問題は見つかりませんでしたが、`[WARN]` の行を確かめてください | 0 |
| `[SKIP]  INCOMPLETE` / `UNKNOWN` | 確かめられなかった項目があります (`--online` でインターネットに接続できないなど) | 2 |

各行の先頭のラベル (`[ OK ]`・`[FAIL]`・`[WARN]`・`[INFO]`・`[SKIP]`) で、項目ごとの結果を示します。端末で実行したときだけ色も付けますが、ラベルの文字だけで意味が分かるようにしています。

## 確かめる内容

| 項目 | 確かめ方 | ネットワーク |
|---|---|---|
| OS の CA 証明書のリスト (urllib、メール送信 (SMTP)、git・Mercurial、Python 3.10 以上かつ pip 24.2 以上の pip (`legacy-certs` で truststore を無効にしたときを除く) と、truststore を有効にした pip が使う) | OpenSSL が読むファイルの指紋。1.6 系では OpenSSL に組み込まれた既定の場所 (シェルの環境変数 `SSL_CERT_FILE` などはデーモンに渡らないので見ません)、2.0 系では `SSL_CERT_FILE`・`SSL_CERT_DIR` があればその場所。git は、これらの環境変数を使わず、組み込まれた既定のファイルを使います。2.0 系でこれらの環境変数が別の場所を指しているときは、git が使う既定のファイルを別の行で確かめます | 使わない |
| certifi (Python の CA 証明書のリスト。`REQUESTS_CA_BUNDLE` が無いときに requests が使う) | `certifi` のファイルの指紋。2.0 系で `REQUESTS_CA_BUNDLE` があるときは、requests が使わないので `[INFO]` で示します | 使わない |
| `REQUESTS_CA_BUNDLE`・`CURL_CA_BUNDLE` (2.0 系の Docker Compose・Docker Swarm の構成) | 指定されたファイル (ディレクトリなら、ハッシュ値の名前のファイル) の指紋。requests 2.32.0〜2.32.4 では、更新の後に再起動が要ることを `[WARN]` で表示します | 使わない |
| 1.6 系のデーモンの環境変数 | `/etc/sysconfig/kompirad`・`kompira_jobmngrd`・`httpd` と、systemd のユニットの `Environment=` (`systemctl edit` で設定したものなど) にある `REQUESTS_CA_BUNDLE`・`CURL_CA_BUNDLE`・`SSL_CERT_FILE`・`SSL_CERT_DIR` が指すファイルの指紋 (ほかの変数は読みません) | 使わない |
| pip | pip が使いうる CA 証明書のリストをすべて合わせた指紋: pip の設定の `cert` (`[global]` と各コマンドの節 (`[install]` など)、`PIP_CERT`)、`REQUESTS_CA_BUNDLE` (無ければ `CURL_CA_BUNDLE`)、pip の中の certifi (`[global]` の `cert` も `PIP_CERT` も無いとき)。ただし、2.0 系で pip が 24.1 より前のときは、`REQUESTS_CA_BUNDLE` か `CURL_CA_BUNDLE` があれば、pip は pip の設定の `cert` よりもそちらを優先して使い、pip の中の certifi も使わないため、そのファイルだけを確かめます。Python 3.10 以上かつ pip 24.2 以上では、pip の中の certifi と OS のリスト (pip はシェルから実行するので、シェルの `SSL_CERT_FILE`・`SSL_CERT_DIR` も反映) も。ただし、pip の設定の `[global]` の `use-deprecated` か `PIP_USE_DEPRECATED` で `legacy-certs` を指定して truststore を無効にしているときは、OS のリストは確かめず、pip の中の certifi も上のとおり `cert` が無いときだけ確かめます (コマンドごとの節で別の値に置き換えているときは、無効にしていないものとして扱います)。Python 3.10 以上で、pip の設定の `use-feature` か `PIP_USE_FEATURE` で truststore を有効にした pip 22.2〜24.1 では、OS のリストも。どれにルートが残っているかを表示します | 使わない |
| 暫定対処 | 信頼を外すファイル (`/etc/pki/ca-trust/source/blocklist` など、2.0 系は `/etc/ca-certificates.conf`) があるか。1.6 系では、OS の修正版を適用した後に消すよう案内します (修正版かどうかは判定しません) | 使わない |
| Kompira のサーバ証明書 | 発行元の名前に eMudhra (emSign) が含まれないか (含まれれば `[WARN]`)。ファイルが無いとき、読めないとき、証明書を読み解けないとき、Apache や RabbitMQ の設定ファイルが読めないときは `[INFO]` (`--cert` で指定したものと、`--certs-only` のときは `[SKIP]`) | `--host` のときだけ |
| 時刻のずれ | pypi.org の時刻と比べます (時刻が大きくずれていると、確認用サイトへの接続が誤って OK になることがあるため、確認用サイトは確かめません) | `--online` |
| TLS を復号するプロキシ | 確認用サイトの証明書が eMudhra の発行のままか | `--online` |
| 確認用サイト | requests と urllib で、偽の証明書を拒否するか (接続できたサイトだけ。発行元を信頼していないという理由で拒否したときだけ `OK` とし、ほかの理由 (ホスト名の不一致など) で拒否したときは `[SKIP]` にします。1.6 系では、デーモンに渡らないシェルの環境変数 (`SSL_CERT_FILE`・`REQUESTS_CA_BUNDLE` など) は使わず、OS の既定のリストと certifi で確かめます。pip は、確認用サイトから届くものを実行しうるため接続せず、上の指紋で判定します) | `--online` |

指紋を確かめる CA 証明書のファイルは、OpenSSL で読み込めるかも確かめます。手で編集したときの書き損じや、証明書をすべて消してしまったことなどで読み込めないファイルは、それを使う HTTPS の接続が失敗するため、ルートの有無とは別に `[FAIL]` にします。

## ご注意

すべて OK でも、Kompira の次の処理は、もともとサーバ証明書を確かめていません。CA 証明書のリストを更新しても、これらの処理は通信経路上のなりすましを見抜けません。

- メールチャネルの受信 (IMAP / POP3)
- LDAP 認証 (LDAPS / StartTLS)
- 2.0 系で、OAuth2 以外の認証を使うメール送信 (SMTP)
- ジョブフローの `urlopen` で `verify=True` を指定しない場合
- Windows リモートジョブの `windows/https-ignore-validation`
- 暗号化しない設定の AMQP と、既定の設定の AMQPS

## ライセンス

MIT License。[LICENSE](../LICENSE) をご覧ください。
