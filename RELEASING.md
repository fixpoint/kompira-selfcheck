# リリースの手順

保守する人向けの手順です。版の付け方は、[README](README.md) の「版とリリース」をご覧ください。

## ブランチ

- `main`: リリースしたもの。リリースのタグは、main のコミットに付けます
- `develop`: 次のリリースに向けて、変更をまとめるブランチ
- トピックブランチ: develop から作り、develop に PR を出してマージします

## 変更するとき (トピックブランチ)

- スクリプトの版 (`TOOL_VERSION`) は変えません
- 変更の内容を、そのスクリプトのディレクトリの `CHANGELOG.md` の「未リリース」の節に書きます

## リリースするとき

1. develop で、変更があったスクリプトごとに次を直し、1 つのコミットにします
   - `TOOL_VERSION` を上げる
   - `CHANGELOG.md` の「未リリース」の節の内容を、新しい版の節 (`## <版>`) に移す
   - ディレクトリの README のダウンロードの URL を、新しい版のタグにする
2. develop から main に PR を出し、マージコミットでマージします (squash や rebase ではマージしません)
3. main のマージコミットに、版を上げたスクリプトごとにタグを付け、Release を作ります。Release の本文には、`CHANGELOG.md` のその版の節を使います

   ```sh
   git switch main && git pull
   d=ca-check f=kompira-ca-check.py v=1.0.0
   grep -qxF "TOOL_VERSION = '$v'" $d/$f || echo "TOOL_VERSION is not $v"
   tmp=$(mktemp -d) && cp $d/$f $tmp/ && (cd $tmp && sha256sum $f > SHA256SUMS)
   git tag -a $d-v$v -m "$d $v" && git push origin $d-v$v
   gh release create $d-v$v --verify-tag --title "$d $v" --notes-file <その版の節を書いたファイル> $tmp/$f $tmp/SHA256SUMS
   ```

4. Release からダウンロードして、`sha256sum -c SHA256SUMS` が通ることを確かめます。告知などにハッシュ値を載せるときは、この値を使います

## 急ぎの修正

main から作ったブランチで直し、上の 1 と同じように版を上げて、main に PR を出します。リリースした後、main を develop にマージします。
