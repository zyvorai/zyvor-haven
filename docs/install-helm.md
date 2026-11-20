# Install with Helm

Installing the Haven chart from the OCI registry.

[Back to the README](https://github.com/zyvorai/haven#readme) · [Documentation map](documentation-map.md)

---

## Helm install

```bash
helm install haven oci://ghcr.io/zyvorai/charts/haven --version 0.1.0 \
  --set controller.enabled=true \
  --set console.enabled=true
```

Images: `ghcr.io/zyvorai/haven-console:0.1.0` · `ghcr.io/zyvorai/haven-controller:0.1.0`. Controller and console default to `enabled: false`; chart installs RBAC by default.
