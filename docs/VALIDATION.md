# 検証結果

2026-11-11にGhidra 12.2 PUBLIC、Temurin Java 25.0.5、Gradle 9.1.0、Linux x86-64で検証しました。

## ビルドとコア

`clean check buildExtension`が成功しました。外部テストフレームワークを必要としないgolden testを`coreTest`と通常の`test`／`check`から実行できます。

- AMACEエンジン: 45項目。論文Table 4の深度・最大深度・観測数、分岐の積集合、SP/BP保存復元、動的スタック、部分レジスタ、内部CFG、unknown、非復帰伝播、20,000ノードを含みます。
- 命令選別: 41項目。列挙順の不変性、同順位の重複保留、優先度、競合による到達性の変化、共有末尾、間接分岐を含みます。
- 抽象ドメイン: 個数制限、集約、飽和加算、overflow、strict-majorityの回帰テストが成功しました。
- 同梱の全Java GhidraScriptを実際のGhidra 12.2 APIに対してコンパイルしました。

## 配布ZIPによるheadless検証

`scripts/test-headless.sh`はExtension ZIPを独立した外部モジュールとして読み込み、一時プロジェクトで次を検証します。通常利用のGhidraや設定は変更しません。

| 入力 | 32bit | 64bit |
| --- | --- | --- |
| Raw Binary | 成功 | 成功 |
| ELF | 成功 | 成功 |
| PE | 成功 | 成功 |

各fixtureで、全位置の候補生成、重複候補、既知の命令開始点10個と関数2個の正確な反映、関数本体、通常callの復帰、キャンセル途中の完全復元、単一Undo/Redo、繰返し実行、ユーザー名・コメントと既存データの保持を確認しました。ELF/PEはローダの入口情報とABI検出、Rawは明示設定を使いました。

同梱の`RunAmace.java`自体を実行し、JSONLのschemaVersion、全26開始位置、全候補の保持、重複する内部命令、採用した命令集合を確認しました。

`AmaceLifterTest.java`の実SLEIGH検証84項目も成功しました。32/64bit、高位アドレス、メモリの穴・未初期化末尾、CALL/RETとCALL-next、間接分岐、部分レジスタ、CMOV/REP内部CFG、IATローダ情報、モード不一致、128/256bitベクトルの扱いを含みます。

## GUI smoke

仮想X11で実際のPluginToolとAmacePluginを生成し、Programの有効化、Rawダイアログ、8列の非同期候補一覧、フィルタ、破棄とconsumer解放を確認しました。

`guiTest`では4096命令の実解析も実行します。通常終了とキャンセルの両方でモーダル画面が1回だけ開くこと、実行中の再実行を防ぐこと、通常終了で4096命令を登録し、キャンセル時は登録しないことを検証しました。AMACE側のTaskLauncherとAutoAnalysisManagerの画面の二重起動を廃止し、解析マネージャが画面を所有する方式へ修正しています。

GUI回帰テストはX11の`DISPLAY`を指定し、`./gradlew guiTest`で実行できます。

## 評価の範囲

小さな既知バイト列と論文の例による機能・回帰検証です。大規模な実バイナリ群での精度評価や、AMACE研究用バックエンドとの出力同一性を示すものではありません。未対応のP-code効果はunknownとして保持します。
