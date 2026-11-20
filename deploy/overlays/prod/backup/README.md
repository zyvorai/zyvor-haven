# Production backups

Do not apply a ScheduledBackup until the Cluster can actually write one.

## Preferred (CNPG 1.26+): Barman Cloud plugin

1. Install the [Barman Cloud CNPG-I plugin](https://cloudnative-pg.io/plugin-barman-cloud/).
2. Create an `ObjectStore` pointing at your bucket.
3. Add the plugin to `Cluster.spec.plugins`.
4. Apply a ScheduledBackup with `method: plugin`.

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: ScheduledBackup
metadata:
  name: platform-db-nightly
  namespace: identity
spec:
  schedule: "0 0 2 * * *"
  backupOwnerReference: self
  cluster:
    name: platform-db
  method: plugin
  pluginConfiguration:
    name: barman-cloud.cloudnative-pg.io
```

## Volume snapshots

If the StorageClass has a CSI snapshotter:

```yaml
spec:
  method: volumeSnapshot
```

`haven backup platform --now` uses this method so a misconfigured object store does not fail the request silently.
