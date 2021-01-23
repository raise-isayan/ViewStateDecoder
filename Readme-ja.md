Microsoft .NET ViewState Parser および Burp suite 拡張 ViewStateDecoder
=============

Language/[English](Readme.md)

このツールは、PortSwigger社の製品であるBurp Suiteの拡張になります。
Burp Pro/Communityに対応しています。

## 概要

この拡張は ASP.NET の ViewStateの表示を行うことが可能なツールです。
なお、コマンドラインを利用してデコードを行うことも可能です。

Burp suite の v2020.3 以降において、 ViewState 表示がされなくなりました。
このため、Burp suite v2020.x 以降のバージョンでの利用を想定しています。

また既存の Burp suite の ViewState にあった一部の問題を修正しています。

## 利用方法

Burp suite の Extenderは以下の手順で読み込めます。

1. [Extender]タブの[add]をクリック
2. [Select file ...]をクリックし、ViewStateDecoder.jar を選択する。
3. ｢Next｣をクリックし、エラーがでてないことを確認後、「Close」にてダイヤログを閉じる。

### Message タブ

__VIEWSTATE のパラメータが存在する場合、History の Message Tabにおいて、「select extension...」ボタンから ViewState を選択できるようになります。

![ViewState-Tree Tab](/image/ViewState-Tree.png)

タブを切り替えてRAW JSONを表示することができます。

![ViewState-JSON Tab](/image/ViewState-JSON.png)

### ViewStateDecoder タブ

![ViewStateDecoder Tab](/image/ViewStateDecoder.png)

- [Decode] ボタン
入力したViewState値をデコードします。

- [Clear] ボタン
デコードした値をクリアします。

## コマンドラインオプション

コマンドラインから ViewState の値をデコードすることが可能です。

```
java -jar ViewStateDecoder.jar -vs=<viewState>
```

<viewState> にデコードしたいViewStateを指定します。レスポンスはJSON形式で出力されます。


例)
```
java -jar ViewStateDecoder.jar -vs=/wEPDwUKLTM0MjUyMzM2OWRkmW75zyss5UROsLtrTEuOq7AGUDk=

{
  "Pair": [
    {
      "Pair": [
        {
          "string": "-342523369"
        },
        null
      ]
    },
    null
  ]
}
```

ViewState が URLEncode されている場合でも URLDecode 後に ViewState が表示されます。

例)
```
java -jar ViewStateDecoder.jar -vs=%2FwEPDwUKLTM0MjUyMzM2OWRkmW75zyss5UROsLtrTEuOq7AGUDk%3D
```

## 実行環境

.Java
* JRE (JDK) 11 (Open JDK is recommended) (https://openjdk.java.net/)

.Burp suite
* v2020 or higher (http://www.portswigger.net/burp/)

## 開発環境
* NetBean 12.2 (https://netbeans.apache.org/)
* Meven 3.6.1 (https://maven.apache.org/)

## 必須ライブラリ
ビルドには別途 [BurpExtLib](https://github.com/raise-isayan/BurpExtLib) のライブラリを必要とします。
* BurpExtlib v2.1.0
  * https://github.com/raise-isayan/BurpExtLib
* google gson
  * https://github.com/google/gson
  * Apache License 2.0
  * https://github.com/google/gson/blob/master/LICENSE

以下のバージョンで動作確認しています。
* Burp suite v2020.12.1

## 注意事項
このツールは、私個人が勝手に開発したもので、PortSwigger社は一切関係ありません。本ツールを使用したことによる不具合等についてPortSwiggerに問い合わせないようお願いします。
