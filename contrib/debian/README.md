
Debian
====================
This directory contains files used to package abled/able-qt
for Debian-based Linux systems. If you compile abled/able-qt yourself, there are some useful files here.

## able: URI support ##


able-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install able-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your able-qt binary to `/usr/bin`
and the `../../share/pixmaps/able128.png` to `/usr/share/pixmaps`

able-qt.protocol (KDE)

