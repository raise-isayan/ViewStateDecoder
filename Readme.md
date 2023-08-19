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

## About the latest version

The main repository (master) may contain code under development.
Please download the stable release version from the following.

* https://github.com/raise-isayan/ViewStateDecoder/releases

Please use the following versions

* Burp suite v2023.1.2 or less than
  * ViewStateDecoder v2.2.14.0 or less than

* Burp suite v2023.1.2 or above
  * ViewStateDecoder v3.0.0 or above 
  * ViewStateDecoder v0.5.3.0 or less (currently available)

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

- [expand] Button
    Expand the selected tree.

- [collapse] Button
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

You can also launch it standalone with the -gui option, which does not require Burp sute.

```
java -jar ViewStateDecoder.jar -gui
```

## build

```
gradlew release
```

## Runtime environment

.Java
* JRE (JDK) 17 (Open JDK is recommended) (https://openjdk.java.net/)

.Burp suite
* v2023.1.2 or higher (http://www.portswigger.net/burp/)

## Development environment
* NetBean 18.0 (https://netbeans.apache.org/)
* Gradle 7.5 (https://gradle.org/)

## Required libraries
Building requires a [BurpExtensionCommons](https://github.com/raise-isayan/BurpExtensionCommons) library.
* BurpExtensionCommons v3.1.x
  * https://github.com/raise-isayan/BurpExtensionCommons

## Use Library

* google gson (https://github.com/google/gson)
  * Apache License 2.0
  * https://github.com/google/gson/blob/master/LICENSE

* Universal Chardet for java (https://code.google.com/archive/p/juniversalchardet/)
  * MPL 1.1
  * https://code.google.com/archive/p/juniversalchardet/

Operation is confirmed with the following versions.
* Burp suite v2023.9.2

## important
This tool developed by my own personal use, PortSwigger company is not related at all. Please do not ask PortSwigger about problems, etc. caused by using this tool.
