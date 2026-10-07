# vmray-sekoia

VMRay integration for Sekoia.io: a Sekoia automation module and the playbooks that use it. An analyst runs a playbook on an alert; VMRay looks up the alert's file hashes or detonates its URL; the full VMRay report is posted on the alert as a comment, with screenshots, and the indicators found are pushed to a Sekoia IOC collection.

## Layout

| Path | Contents |
|---|---|
| [`VMRay/`](VMRay/) | The automation module. [`VMRay/README.md`](VMRay/README.md) covers configuration, actions, playbooks, the comment layout, known limitations and development. |
| [`VMRay/CHANGELOG.md`](VMRay/CHANGELOG.md) | Release history. |
| [`playbooks/`](playbooks/) | Sekoia playbooks to import — described in [`VMRay/README.md`](VMRay/README.md#playbooks). |
