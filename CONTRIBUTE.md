# Contributing

Thanks for helping improve Snitch.

## Before you start

- Open an issue for bugs or larger changes.
- Keep changes focused and small.
- Follow the existing code style and project structure.

## Local checks

Run the app locally before opening a pull request:

```powershell
dotnet restore
dotnet build .\snitch.csproj
dotnet run --project .\snitch.csproj
```

## Pull requests

- Describe what changed and why.
- Include screenshots or short notes for UI changes when useful.
- Link the related issue if there is one.

## Releases

- Update [CHANGELOG.md](./CHANGELOG.md) before tagging a release.
- The release workflow publishes the changelog alongside the MSIX artifacts.
