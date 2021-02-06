Microsoft .NET ViewState Parser and Burp suite extension ViewStateDecoder
=============

Language/[Japanese](Readme-ja.md)

This tool is an extension of PortSwigger product, Burp Suite.
Supports Burp suite Professional/Community.


## Overview

This extension is a tool that allows you to display ViewState of ASP.NET.
Note that it is also possible to decode using the command line.

ViewState has been hidden in Burp suite since v2020.3.
It is intended for use with Burp suite v2020.x or later.

Fixed some issues with ViewState in the existing Burp suite.

## How to Use

The Burp Suite Extender can be loaded by following the steps below.

1. Click [add] on the [Extender] tab
2. Click [Select file ...] and select BigIPDiscover.jar.
3. Click [Next], confirm that no error is occurring, and close the dialog with [Close].

### Message Tab

If the __VIEWSTATE parameter exists, you can select the ViewState from the "select extension..." button in the Message Tab of History. button on the Message Tab of the History to select the ViewState.

![ViewState-Tree Tab](/image/ViewState-Tree.png)

Switch tabs to view Raw JSON.

![ViewState-JSON Tab](/image/ViewState-JSON.png)

### ViewStateDecoder Tab

![ViewStateDecoder Tab](/image/ViewStateDecoder.png)

- [expand] Button::
    Expand the selected tree.

- [collapse] Button::
    Collapse the selected tree.

- [Decode] Button
Decode the ViewState value.

- [Clear] Button
Clear the decoded value.

## Command line option

It is possible to decode the value of ViewState from the command line.

```
java -jar ViewStateDecoder.jar -vs=<viewState>
```

Specify the ViewState to be decoded in <viewState>. The response will be output in JSON format.

example)
```
java -jar ViewStateDecoder.jar -vs=/wEPDwUKLTM0MjUyMzM2OWRkmW75zyss5UROsLtrTEuOq7AGUDk=

MAC: true
digest: 996ef9cf2b2ce5444eb0bb6b4c4b8eabb0065039
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

Even if the ViewState is URLEncoded, the ViewState will be output after URLDecode.

example)
```
java -jar ViewStateDecoder.jar -vs=%2FwEPDwUKLTM0MjUyMzM2OWRkmW75zyss5UROsLtrTEuOq7AGUDk%3D
```

## build

```
gradlew build
```

## Runtime environment

.Java
* JRE (JDK) 11 (Open JDK is recommended) (https://openjdk.java.net/)

.Burp suite
* v2020 or higher (http://www.portswigger.net/burp/)

## Development environment
* NetBean 12.2 (https://netbeans.apache.org/)
* Gradle 6.8.1 (https://gradle.org/)

## Required libraries
Build requires a separate library of [BurpExtLib](https://github.com/raise-isayan/BurpExtLib).
* BurpExtlib v2.1.2.0

## Use Library

* google gson (https://github.com/google/gson)
  * Apache License 2.0
  * https://github.com/google/gson/blob/master/LICENSE

Operation is confirmed with the following versions.
* Burp suite v2020.12.1

## important
This tool developed by my own personal use, PortSwigger company is not related at all. Please do not ask PortSwigger about problems, etc. caused by using this tool.
