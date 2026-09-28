#!/usr/bin/env python3
"""Check the staged production Helm transport contract in both gate states."""

import pathlib
import re
import subprocess


CHART = pathlib.Path(__file__).resolve().parents[1] / "charts/osac"
HOOKS = {
    "fulfillment-create-hub",
    "create-network-class",
    "seed-cluster-versions",
    "register-local-storage",
    "osac-publish-templates",
}


def render(enabled):
    cmd = [
        "helm", "template", "osac", str(CHART),
        "--values", str(CHART / "ci/default-values.yaml"),
        "--set", f"global.fulfillmentTrust.enabled={str(enabled).lower()}",
        "--set", "global.osacDeploymentId=ci/osac",
        "--set", "metering.enabled=true",
        "--set", "lvms.enabled=true",
        "--set", "hubAccess.enabled=true",
        "--set", "clusterVersions.enabled=true",
        "--set", "aap.instanceGroups.publishTemplates.enabled=true",
    ]
    manifest = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    return [doc for doc in manifest.split("\n---\n") if doc.strip()]


def select(docs, source, name=None):
    matches = [doc for doc in docs if f"# Source: {source}\n" in doc]
    if name:
        matches = [doc for doc in matches if "kind: Job\n" in doc and f"  name: {name}\n" in doc]
    if len(matches) != 1:
        raise AssertionError(f"expected one rendered {source} {name or ''}, found {len(matches)}")
    return matches[0]


def check(enabled):
    docs = render(enabled)
    operator = select(docs, "osac/charts/operator/templates/deployment.yaml")
    metering = select(docs, "osac/charts/metering/templates/deployment.yaml")
    assert "mountPath: /etc/ca-bundle" in metering
    assert "readOnly: true" in metering
    assert "key: bundle.pem" in metering
    assert "name: ca-bundle" in metering
    for marker in ("mountPath: /etc/ca-bundle", "name: fulfillment-ca-bundle", "key: bundle.pem"):
        assert (marker in operator) == enabled
    assert "value: /etc/ca-bundle/bundle.pem" in metering
    assert f'value: "{str(enabled).lower()}"' in metering
    assert ("--fulfillment-ca-file=/etc/ca-bundle/bundle.pem" in operator) == enabled
    assert ("--grpc-insecure" in operator) != enabled

    for name in HOOKS:
        source = f"osac/templates/hooks/{name}.yaml"
        if name == "fulfillment-create-hub":
            source = "osac/templates/hooks/create-hub.yaml"
        elif name == "osac-publish-templates":
            source = "osac/templates/hooks/publish-templates.yaml"
        job = select(docs, source, name)
        for marker in ("mountPath: /etc/ca-bundle", "key: bundle.pem", "name: ca-bundle"):
            assert (marker in job) == enabled, name
        if enabled:
            assert "readOnly: true" in job, name
            assert "curl -sf --cacert /etc/ca-bundle/bundle.pem" in job, name
            assert not re.search(r"curl\s+[^\n]*\s(?:-k|--insecure)(?:\s|$)", job), name
        else:
            assert "curl -sf -k" in job, name


if __name__ == "__main__":
    check(False)
    check(True)
    print("Fulfillment trust production render checks passed.")
