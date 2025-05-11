---
title: APK
layout: post
date: 2025-05-05
description: "APK files are the package format used by Android. They are similar to ZIP files and contain all the necessary files for an Android application."
permalink: /theory/mobile/apk
---

# APK Overview
APK (Android Package Kit) files are the package format used by Android to distribute and install applications. They are similar to ZIP files and contain all the necessary files for an Android application, including the code, resources, assets, and manifest file.

## APK Structure
An APK file is essentially a ZIP archive that contains the following components:
- **META-INF**: Contains the manifest file and signature information.
- **res**: Contains the resources used by the application, such as images, layouts, and strings.
- **lib**: Contains the compiled native libraries for different CPU architectures.
- **assets**: Contains raw asset files that can be accessed by the application.
- **classes.dex**: Contains the compiled Java bytecode for the application.
- **AndroidManifest.xml**: Contains essential information about the application, such as its package name, permissions, and components (activities, services, etc.).

## APK Decompilation
Decompiling an APK file allows you to inspect its contents and understand how it works. This can be useful for reverse engineering, security analysis, or simply learning about Android development.

### Tools for Decompiling APKs
- [**APKTool**](https://apktool.org/): A tool for reverse engineering Android APK files. It can decode resources to nearly original form and rebuild them after making some modifications.
- [**JD-GUI**](https://github.com/java-decompiler/jd-gui): A standalone graphical utility that displays Java source codes of “.class” files. It can be used to view the decompiled Java code from DEX files.
- [**MobSF**](https://github.com/MobSF/Mobile-Security-Framework-MobSF): Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS) pen-testing framework capable of performing static and dynamic analysis.
