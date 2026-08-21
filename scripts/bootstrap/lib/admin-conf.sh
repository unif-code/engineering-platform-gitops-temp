#!/usr/bin/env bash

# admin.conf 的 cluster/context 名由 kubeadm 依据 host.env 的 HOST_CLUSTER_NAME 生成，
# server 由 HOST_NODE_IP 派生；调用方须先完成 load_host_config。

admin_conf_json_is_exact() {
  python_isolated -c '
import base64
import json
import sys

cluster_name, context_name, user_name, server = sys.argv[1:5]

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result

def reject_constant(_value):
    raise ValueError("non-finite number")

def valid_base64(value):
    if not isinstance(value, str) or not value:
        return False
    try:
        return bool(base64.b64decode(value, validate=True))
    except (ValueError, TypeError):
        return False

try:
    document = json.load(
        sys.stdin,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    if not isinstance(document, dict):
        raise ValueError
    required = {
        "apiVersion", "kind", "clusters", "contexts",
        "current-context", "users",
    }
    keys = set(document)
    if keys == required | {"preferences"}:
        # kubectl v1.36 省略空 preferences；若被序列化出来必须是空对象。
        if document["preferences"] != {}:
            raise ValueError
    elif keys != required:
        raise ValueError
    clusters = document["clusters"]
    contexts = document["contexts"]
    users = document["users"]
    if (
        document["apiVersion"] != "v1" or document["kind"] != "Config" or
        document["current-context"] != context_name or
        not isinstance(clusters, list) or len(clusters) != 1 or
        not isinstance(contexts, list) or len(contexts) != 1 or
        not isinstance(users, list) or len(users) != 1
    ):
        raise ValueError
    cluster_record = clusters[0]
    context_record = contexts[0]
    user_record = users[0]
    if (
        not isinstance(cluster_record, dict) or
        set(cluster_record) != {"name", "cluster"} or
        cluster_record.get("name") != cluster_name or
        not isinstance(cluster_record.get("cluster"), dict) or
        set(cluster_record["cluster"]) != {"server", "certificate-authority-data"} or
        cluster_record["cluster"].get("server") != server or
        not valid_base64(cluster_record["cluster"].get("certificate-authority-data"))
    ):
        raise ValueError
    if (
        not isinstance(context_record, dict) or
        set(context_record) != {"name", "context"} or
        context_record.get("name") != context_name or
        context_record.get("context") != {
            "cluster": cluster_name, "user": user_name
        }
    ):
        raise ValueError
    if (
        not isinstance(user_record, dict) or
        set(user_record) != {"name", "user"} or
        user_record.get("name") != user_name or
        not isinstance(user_record.get("user"), dict) or
        set(user_record["user"]) != {
            "client-certificate-data", "client-key-data"
        } or
        not valid_base64(user_record["user"].get("client-certificate-data")) or
        not valid_base64(user_record["user"].get("client-key-data"))
    ):
        raise ValueError
except (KeyError, TypeError, ValueError):
    raise SystemExit(1)
' "$HOST_CLUSTER_NAME" "kubernetes-admin@${HOST_CLUSTER_NAME}" \
    kubernetes-admin "https://${HOST_NODE_IP}:6443" >/dev/null 2>&1
}
