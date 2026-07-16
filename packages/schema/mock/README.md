# Mock data

This directory contains JSON fixtures for Web and CLI development while the
repository backend is being built.

## Directory structure

```
mock/
├── packages.json
└── versions/                              # example fixtures; not exhaustive
    ├── code-review-skill-1.0.0.json        # example
    └── risky-executor-0.1.0.json           # example
```

The directory may contain additional version fixtures beyond these examples.

## Consumer API contract

- Public routes expose only explicit `published` package/version records.
- Every package row has an explicit matching version JSON document.
- Install manifests are available at
  `/api/v0/packages/{name}/install-manifest?client=...`.
- The generated contract is
  `packages/schema/openapi/consumer-v0.1.json`.
- These JSON files are development fixtures; persistence is provided later by
  the repository backend.

## Using the fixtures

Web and CLI code may import or read these JSON files directly during local
development. When the backend is available, point clients at
`http://localhost:8000/api/v0` and use the published Consumer API routes.
