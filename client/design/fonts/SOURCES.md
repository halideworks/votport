# Bundled fonts

Variable TrueType files from the google/fonts repository, SIL Open Font
License 1.1 (the OFL text beside each family ships with every app build).

- PlusJakartaSans-Variable.ttf: https://raw.githubusercontent.com/google/fonts/main/ofl/plusjakartasans/PlusJakartaSans%5Bwght%5D.ttf
- JetBrainsMono-Variable.ttf: https://raw.githubusercontent.com/google/fonts/main/ofl/jetbrainsmono/JetBrainsMono%5Bwght%5D.ttf

Fetched 2026-09-05. The web pages carry latin woff2 subsets of the same
families under web/assets/fonts (scripts/fetch-fonts.sh); AppKit and WinUI
need TrueType, hence the second copy. Refresh both when a family changes.
