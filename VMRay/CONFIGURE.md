## Configuration

Look up file hashes in VMRay or detonate URLs from a Sekoia.io playbook, post the full VMRay report on the alert as a comment (with screenshots), and push the indicators found to a Sekoia.io IOC collection.

### Requirements

- A VMRay Platform account, cloud (e.g. `https://eu.cloud.vmray.com`, `https://us.cloud.vmray.com`) or on-premises, running VMRay Platform **2026.2 or later**. On older versions, the recursive threat names and classifications of child samples are missing from the report.
- To detonate URLs (`Submit URL Sample` action), a VMRay plan that allows submissions: VMRay rejects submissions on the DeepResponse plan. Looking up hashes works on every plan and consumes no quota; every URL detonation consumes quota.

### In VMRay: Create an API key

1. Sign in to the VMRay Platform with the user Sekoia.io will act as.
2. Open your user profile and go to the API keys section.
3. Create an API key and copy it. You will use it in the next steps.

### In Sekoia.io: Connect the VMRay integration

4. In Sekoia.io, open `Integrations` from the sidebar.
5. Search for `VMRay` and select the VMRay integration from the results.
6. Click `Show accounts`, then `Connect an account`.
7. Fill in the `Add new account` form:

    - `Give a name to this account`: a label of your choice (e.g. `VMRay`).
    - `Base URL`: the URL of your VMRay Platform, e.g. `https://eu.cloud.vmray.com`.
    - `Api Key`: the API key created in VMRay.
    - `Verify SSL`: keep it enabled. Disable it only for an on-premises appliance with a self-signed certificate.

    Click `Add account`.

### In Sekoia.io: Use the VMRay actions in a playbook

8. Open or create a playbook, add the VMRay actions, and select the VMRay account you just connected in each one's `Account` tab. A typical chain:

    - `Get Samples By Hash` (file hashes of the alert) or `Submit URL Sample` (a URL of the alert),
    - then `Build Report` with the `sample_ids` or `submission_ids` they return,
    - then `Render Report` and the Sekoia.io `Comment Alert` action to post the report on the alert, with a `Foreach` over `screenshot_comments` for the screenshots,
    - and `Extract IOCs` with the Sekoia.io `Add IOC to IOC Collection` action to push the indicators, with a `Foreach` over `indicator_groups`.

Ready-made playbooks are available as templates: "VMRay: Report on demand (Hash + URL)", run by an analyst on an alert, and "VMRay: Report on alert creation (Hash + URL)", run on every new alert. After creating a playbook from one, select your VMRay account on the VMRay nodes and set the IOC collection on both `Add IOCs to IOC Collection` nodes. For the alert-creation template, consider limiting its trigger to specific rules, since every URL detonation consumes quota.
