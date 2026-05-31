# Assets

Drop the NuGet package icon here as `icon.png` (recommended **128×128 PNG**, transparent background, under 1 MB).

The library `.csproj` is wired to pack it conditionally — once `assets/icon.png` exists, **also** uncomment the `<PackageIcon>icon.png</PackageIcon>` line in `src/PostQuantum.Cryptography/PostQuantum.Cryptography.csproj` and the icon will appear in:

- nuget.org search and package detail pages
- Visual Studio's Package Manager UI
- `dotnet add package` output where supported

No icon is checked in by default — branding is a decision for the package owner, not something to ship a placeholder for.
