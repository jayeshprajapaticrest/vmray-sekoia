# vmray-sekoia

VMRay integration for Sekoia.io: a Sekoia automation module and the playbooks that use it. An analyst runs a playbook on an alert; VMRay looks up the alert's file hashes or detonates its URL; the full VMRay report is posted on the alert as a comment, with screenshots, and the indicators found are pushed to a Sekoia IOC collection.

## Layout

| Path | Contents |
|---|---|
| [`VMRay/`](VMRay/) | The automation module. [`VMRay/CONFIGURE.md`](VMRay/CONFIGURE.md) covers setup; [`VMRay/README.md`](VMRay/README.md) covers the actions, the playbook templates, the comment layout, known limitations and development. |
| [`VMRay/CHANGELOG.md`](VMRay/CHANGELOG.md) | Release history. |
| [`playbooks/templates/`](playbooks/templates/) | The "Report on demand" and "Report on alert creation" playbooks as Sekoia playbook templates, without tenant-specific identifiers. |

## Playbooks

| File | What it is |
|---|---|
| `playbooks/templates/vmray_report_on_demand.json` | "VMRay: Report on demand (Hash + URL)" template — Manual trigger. Listed in `playbooks/templates/playbooks.json`, in the [SEKOIA-IO/Community](https://github.com/SEKOIA-IO/Community) template format. |
| `playbooks/templates/vmray_report_on_alert_creation.json` | "VMRay: Report on alert creation (Hash + URL)" template — Alert Created trigger. |

The templates carry none of a tenant's identifiers (`trigger_configuration_uuid`, `module_configuration_uuid`, `community_uuid`), and their IOC collection is the placeholder `ioc-collection--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. What they do is described in [`VMRay/README.md`](VMRay/README.md#playbook-templates). `VMRay/tests/data/vmray_report_on_demand.json` is a copy of the on-demand template used by the module's tests; a test keeps it identical to the published one.
