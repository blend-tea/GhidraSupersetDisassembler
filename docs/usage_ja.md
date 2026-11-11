# 利用ガイド

[English](usage.md) | **日本語**

## 入力の指定

ELF／PEはローダが読み込んだメタデータから入口を取得します。ABIはELFではSystem V、PEではWindowsを既定とし、32／64bitは取込済みLanguageから決定します。既知関数の個別の呼出規約は、stack cleanupなどの解析に反映します。標準では初期化済み実行領域を解析します。対象を限定したい場合はListingの範囲を選択してから実行してください。

Raw Binaryには信頼できる入口・ABIの情報がないため、実行ダイアログで次を指定します。

| 項目 | 内容 |
| --- | --- |
| Entry address | 実際に処理を開始するアドレス。解析範囲内の初期化済みメモリを指定 |
| First / Last address | 解析範囲。両端を含む |
| ABI | `SYSV_X86`、`SYSV_X64`、`WINDOWS_X86`、`WINDOWS_X64`から取込済み命令モードに合うものを選択 |

アドレスはGhidraが表示するアドレス表記を使います。RawのLanguage・32／64bitモード・ベースアドレスは取込時に指定したものを使います。

## 候補一覧

| 列 | 内容 |
| --- | --- |
| Address / Bytes / Instruction | デコードした候補。通常Listingと異なる開始位置や重複も表示 |
| Pointer definedness | 後方解析が要求するレジスタ定義条件 |
| Stack depth | 深度・最大深度・観測数の要約 |
| Callee-saved registers | 呼出規約で保存すべきレジスタの保存・復元解析 |
| Selection / Details | 採用・保留とその理由、未対応／不確実な要因 |

フィルタ欄ではアドレス、命令名、理由などを検索できます。ヘッダをクリックすると列で並べ替えられます。行のダブルクリックで、その候補が属するProgramのListingへ移動します。重複候補は通常Listingに同時登録できないため、移動先では別の採用済み命令の内部になる場合があります。

Programを変更すると一覧をstaleとして表示します。Programを切り替えるか閉じると一覧を解除します。変更後の候補を確認する場合は再実行してください。

## 自動反映と既存Program

解析中は通常の自動解析と直列化します。解析で採用した集合だけを反映し、その変更をきっかけに別の解析が命令を増やすことを抑止します。その後ユーザーが通常のAuto Analyzeを実行した場合は、Ghidra側の規則で結果が追加・変更されます。

GUIの進捗・キャンセル画面はGhidraの解析マネージャが1つだけ表示します。Extension側で別のモーダルTaskLauncherは起動しません。解析中の再実行は無効になります。

候補の生成中にはProgramを書き換えません。反映は一つのtransactionにまとめ、反映中の失敗やキャンセル時は元に戻します。GUIのUndo／Redoで適用を戻せます。既存の競合命令と定義済みデータは消去せず、候補側に競合理由を記録します。

入口と非復帰性を推定できても、通常Listingへ忠実に表現できない重複や共有関数本体は残ります。命令の採用と関数の作成は別に判定し、関数本体の競合時には命令を残して関数作成を保留する場合があります。

## 解析の境界

- x86の32bitまたは64bit固定モードを使います。16bitモード、実行中のモード切替、自己書換え、実行時に生成されるコードはこの静的解析の対象に含めません。
- メモリの穴や未初期化領域を架空のバイトで補完しません。範囲末尾から後続メモリへ延びる命令候補は保持しますが、自動反映には命令全体が解析範囲内に収まる必要があります。
- 間接分岐先の完全復元や、全関数の完全回収は保証しません。外部転送・未解決の分岐先は結果に残します。
- P-code上で扱えない効果はunknownにします。候補そのものは削除せず、未対応命令をNOPとして解析しません。
- AMACE論文の後方解析と、Ghidraの命令選別・関数本体生成は区別されます。論文の実験値やC++研究実装との出力一致を、そのままこのJava移植の精度として主張しません。

## headless引数

`RunAmace.java`はGUIと同じサービスを直接呼び出します。

| 引数 | 内容 |
| --- | --- |
| `--abi NAME` | ABIを明示。Rawでは必須 |
| `--entry ADDRESS` | 信頼する入口を追加。Rawでは必須 |
| `--start ADDRESS --end ADDRESS` | 両端を含む解析範囲 |
| `--no-apply` | 候補生成・解析・選別のみ実行 |
| `--report PATH` | JSON Linesレポートの出力先。概要、全候補、未解決分岐を記録 |

Ghidra側の`-processor`、`-cspec`、`-loader`、`-loader-baseAddr`等は`RunAmace.java`の引数ではなく、`analyzeHeadless`の取込オプションです。Rawの入口は、指定したベースアドレスで読み込まれた初期化済みメモリのうち、解析範囲内の実際の開始位置を指定します。入口がイメージベースと同じである必要はありません。

## Java APIからの利用

GUIとheadlessスクリプトは次のサービスを共有します。

```java
AnalysisReport report = new AmaceAnalysisService().run(
    program, scope, new AnalysisOptions(abi, trustedEntries, true), monitor);
```

`apply=true`の呼出しは既存のProgram transactionの外から行ってください。サービスが解析との直列化と適用transactionを管理します。SwingのEDTではなくバックグラウンドスレッドから実行します。

GhidraScriptは初期transactionを持つため、同梱の`RunAmace.java`は`end(true)`でそのtransactionを閉じてからサービスを呼びます。独自スクリプトも、サービスへ変更のrollbackを委ねられるよう、開始済みtransactionの中へ適用処理を入れないでください。

## 検証の実行

Java 25とGhidra 12.2を指定してビルドし、解析・選別のgolden／propertyテストを実行します。

```sh
./gradlew clean buildExtension coreTest
```

パッケージ化したZIPに対する統合テストは次のコマンドで実行します。Python 3で小さなバイト列からELF・PE・Rawの32／64bit fixtureを生成し、`analyzeHeadless -noanalysis`で6通りを検証します。通常のユーザー設定や既存プロジェクトへExtensionをインストールせず、一時領域の外部モジュールとして読み込みます。

```sh
scripts/test-headless.sh
```

対象には、全位置のデコード、重複候補、正確なListingの採用集合、関数本体、既存定義の保護、キャンセル・失敗時のrollback、再実行、Undo／Redoが含まれます。`AMACE_KEEP_TEST_OUTPUT=1`を付けると、一時プロジェクトとログを残して確認できます。

`ghidra_scripts/AmaceLifterTest.java`は実際のSLEIGHデコーダを使った追加の検証です。高位アドレス、範囲末尾、未初期化メモリと穴、CALL／RETの正規化、部分レジスタ、P-code内分岐、未知USEROP、呼出規約を扱います。

開発時のGUI smokeでは、仮想X11上でGhidra 12.2のPluginToolと`AmacePlugin`を生成し、Programの有効化、Raw設定画面、8列の候補テーブル、非同期ロード、フィルタ部品、Program consumerの解放と破棄を確認しています。
