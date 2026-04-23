import json
import os
import re
import subprocess
import pandas as pd

# regex driven pattern matching
CONTROL_PATTERNS: dict[str, list[str]] = {
 
    # -------------------------------------------------------------------------
    # Workload / Container Security
    # -------------------------------------------------------------------------
    'C-0001': [
        r'forbidden.{0,5}registr',
        r'container.{0,5}registr',
        r'disallowed.{0,5}registr',
        r'blocked.{0,5}registr',
    ],
    'C-0002': [
        r'command.{0,5}exec(ution)?',
        r'allow.{0,5}exec',
        r'exec.{0,5}(in)?to.{0,5}container',
        r'kubectl.{0,5}exec',
    ],
    'C-0004': [
        r'memory.{0,5}(limit|request)',
        r'(limit|request).{0,5}memory',
        r'resource.{0,5}memory',
    ],
    'C-0009': [
        r'resource.{0,5}limit',
        r'limit.{0,5}resource',
        r'cpu.{0,5}(limit|request)',
        r'memory.{0,5}(limit|request)',
    ],
    'C-0012': [
        r'credentials?.{0,5}(in|inside).{0,5}config',
        r'config.{0,5}(file|map).{0,5}(secret|password|token|credential)',
        r'application.{0,5}credential',
        r'secret.{0,5}(in|inside).{0,5}(config|env)',
        r'hardcoded.{0,5}(secret|password|token)',
    ],
    'C-0013': [
        r'non.?root',
        r'run.{0,5}as.{0,5}root',
        r'root.{0,5}container',
        r'runAsNonRoot',
        r'runAsUser.{0,5}0',
    ],
    'C-0016': [
        r'allow.?privilege.?escalat',
        r'privilege.?escalat',
        r'allowPrivilegeEscalation',
    ],
    'C-0017': [
        r'immutable.{0,5}(container|filesystem|rootfs)',
        r'readOnlyRootFilesystem',
        r'read.?only.{0,5}(root|filesystem)',
    ],
    'C-0018': [
        r'readiness.{0,5}probe',
        r'probe.{0,5}readiness',
    ],
    'C-0026': [
        r'cron.?job',
        r'kubernetes.{0,5}cron',
        r'scheduled.{0,5}job',
    ],
    'C-0038': [
        r'host.?pid',
        r'host.?ipc',
        r'hostPID',
        r'hostIPC',
        r'pid.{0,5}namespace',
        r'ipc.{0,5}namespace',
    ],
    'C-0041': [
        r'host.?network',
        r'hostNetwork',
        r'host.{0,5}network.{0,5}(access|namespace)',
    ],
    'C-0042': [
        r'ssh.{0,5}(server|service|daemon|running)',
        r'sshd.{0,5}container',
        r'openssh',
    ],
    'C-0044': [
        r'host.?port',
        r'container.{0,5}host.{0,5}port',
        r'hostPort',
    ],
    'C-0045': [
        r'writable.{0,5}host.?path',
        r'hostPath.{0,5}writ',
        r'host.?path.{0,5}write',
    ],
    'C-0046': [
        r'insecure.{0,5}capabilit',
        r'linux.{0,5}capabilit',
        r'net.?raw',
        r'sys.?admin',
        r'cap.{0,5}add',
        r'dangerous.{0,5}capabilit',
    ],
    'C-0048': [
        r'host.?path.{0,5}(mount|volume)',
        r'hostPath',
        r'mount.{0,5}host.{0,5}(path|dir|filesystem)',
    ],
    'C-0050': [
        r'cpu.{0,5}(limit|request)',
        r'(limit|request).{0,5}cpu',
        r'resource.{0,5}cpu',
    ],
    'C-0052': [
        r'instance.{0,5}metadata.{0,5}(api|service)',
        r'metadata.{0,5}(endpoint|api)',
        r'169\.254\.169\.254',
        r'imds',
    ],
    'C-0053': [
        r'access.{0,5}(container|pod).{0,5}service.{0,5}account',
        r'service.{0,5}account.{0,5}(access|token|mount)',
    ],
    'C-0055': [
        r'linux.{0,5}harden',
        r'harden.{0,5}linux',
        r'seccomp',
        r'apparmor',
        r'selinux',
        r'security.{0,5}(profile|context|module)',
    ],
    'C-0056': [
        r'liveness.{0,5}probe',
        r'probe.{0,5}liveness',
    ],
    'C-0057': [
        r'privileged.{0,5}container',
        r'privileged.{0,5}mode',
        r'privileged.{0,5}true',
        r'runAsPrivileged',
    ],
    'C-0062': [
        r'sudo.{0,5}(container|entrypoint|cmd)',
        r'entrypoint.{0,5}sudo',
        r'run.{0,5}sudo',
    ],
    'C-0073': [
        r'naked.{0,5}pod',
        r'bare.{0,5}pod',
        r'pod.{0,5}(not|without).{0,10}(deployment|replicaset|controller)',
        r'unmanaged.{0,5}pod',
    ],
    'C-0074': [
        r'container.{0,5}runtime.{0,5}socket',
        r'docker\.sock',
        r'containerd\.sock',
        r'crio\.sock',
        r'runtime.{0,5}socket.{0,5}mount',
    ],
    'C-0075': [
        r'image.{0,5}pull.{0,5}(policy|latest)',
        r'latest.{0,5}tag',
        r'pull.{0,5}(always|ifnotpresent).{0,10}latest',
        r'imagePullPolicy',
    ],
    'C-0076': [
        r'label.{0,5}(usage|missing|required)',
        r'(missing|no).{0,5}label',
        r'resource.{0,5}label',
    ],
    'C-0077': [
        r'k8s.{0,5}(common|recommended).{0,5}label',
        r'app\.kubernetes\.io',
        r'common.{0,5}label',
    ],
    'C-0078': [
        r'allowed.{0,5}registr',
        r'image.{0,5}(from|source).{0,5}(allowed|approved|trusted)',
        r'trusted.{0,5}registr',
        r'approved.{0,5}registr',
    ],
    'C-0061': [
        r'(pod|workload).{0,5}default.{0,5}namespace',
        r'default.{0,5}namespace.{0,5}(pod|workload)',
        r'deployed.{0,10}default.{0,5}namespace',
    ],
    'C-0212': [
        r'default.{0,5}namespace.{0,5}(should.{0,5}not|not.{0,5}use)',
        r'(avoid|restrict).{0,5}default.{0,5}namespace',
        r'namespace.{0,5}default.{0,5}use',
    ],
 
    # -------------------------------------------------------------------------
    # RBAC / Access Control
    # -------------------------------------------------------------------------
    'C-0007': [
        r'(role|clusterrole).{0,5}delete.{0,5}(capabilit|permission|verb)',
        r'delete.{0,5}(capabilit|permission).{0,5}(role|rbac)',
        r'rbac.{0,5}delete',
    ],
    'C-0014': [
        r'kubernetes.{0,5}dashboard',
        r'dashboard.{0,5}access',
        r'k8s.{0,5}dashboard',
    ],
    'C-0015': [
        r'list.{0,5}(kubernetes.{0,5})?secrets?',
        r'secret.{0,5}list.{0,5}(access|permission|verb)',
        r'rbac.{0,5}list.{0,5}secret',
    ],
    'C-0031': [
        r'delete.{0,5}(kubernetes.{0,5})?events?',
        r'event.{0,5}delete.{0,5}(permission|rbac)',
    ],
    'C-0034': [
        r'automatic.{0,5}(service.{0,5}account.{0,5}(mount|mapping)|token.{0,5}mount)',
        r'automountServiceAccountToken',
        r'auto.{0,5}mount.{0,5}service.{0,5}account',
    ],
    'C-0035': [
        r'admin(istrative)?.{0,5}role',
        r'cluster.?admin',
        r'clusterrole.{0,5}admin',
        r'broad.{0,5}(permission|access|role)',
    ],
    'C-0063': [
        r'port.?forward(ing)?',
        r'portforward.{0,5}(privilege|permission|rbac)',
    ],
    'C-0065': [
        r'(no|disable|prevent).{0,5}impersonat',
        r'impersonat.{0,5}(privilege|permission|rbac)',
        r'user.{0,5}impersonat',
    ],
    'C-0088': [
        r'rbac.{0,5}(enabled|active|configured)',
        r'role.?based.{0,5}access.{0,5}control',
        r'enable.{0,5}rbac',
    ],
    'C-0185': [
        r'cluster.?admin.{0,5}(role|limited|restrict)',
        r'minimize.{0,5}cluster.?admin',
        r'cluster.?admin.{0,5}(only|where.{0,5}required)',
    ],
    'C-0186': [
        r'minimize.{0,5}access.{0,10}secret',
        r'secret.{0,5}(access|permission).{0,5}(limit|minimiz|restrict)',
    ],
    'C-0187': [
        r'wildcard.{0,5}(role|clusterrole|rbac)',
        r'\*.{0,5}(verb|resource|apigroup)',
        r'(role|clusterrole).{0,5}wildcard',
    ],
    'C-0188': [
        r'(minimize|restrict).{0,5}(access.{0,5})?create.{0,5}pod',
        r'pod.{0,5}create.{0,5}(permission|rbac)',
    ],
    'C-0189': [
        r'default.{0,5}service.{0,5}account.{0,5}(not.{0,5}(active|used)|inactive)',
        r'(disable|avoid).{0,5}default.{0,5}service.{0,5}account',
    ],
    'C-0190': [
        r'service.{0,5}account.{0,5}token.{0,5}(only|mount|necessary)',
        r'automount.{0,5}(only.{0,5}where.{0,5}necessary)',
    ],
    'C-0191': [
        r'(bind|escalate|impersonat).{0,5}(permission|privilege|rbac)',
        r'limit.{0,5}(bind|escalate|impersonat)',
    ],
    'C-0246': [
        r'system:masters',
        r'masters.{0,5}group',
        r'avoid.{0,5}system.{0,5}masters',
    ],
    'C-0262': [
        r'anonymous.{0,5}(user|subject).{0,5}(rolebinding|role|rbac)',
        r'rolebinding.{0,5}anonymous',
        r'system:anonymous.{0,5}(role|binding)',
    ],
    'C-0265': [
        r'system:authenticated.{0,5}elevated',
        r'authenticated.{0,5}(elevated|admin|cluster.?admin).{0,5}role',
    ],
    'C-0267': [
        r'(workload|pod).{0,5}cluster.{0,5}takeover',
        r'cluster.{0,5}takeover.{0,5}role',
    ],
    'C-0272': [
        r'(workload|pod).{0,5}admin(istrative)?.{0,5}role',
        r'admin.{0,5}(permission|access).{0,5}workload',
    ],
    'C-0278': [
        r'(minimize|restrict).{0,5}access.{0,10}(create.{0,5})?persistent.{0,5}volume',
        r'pv.{0,5}create.{0,5}(permission|rbac)',
    ],
    'C-0279': [
        r'proxy.{0,5}sub.?resource.{0,5}node',
        r'node.{0,5}proxy.{0,5}(access|permission)',
    ],
    'C-0280': [
        r'approval.{0,5}sub.?resource.{0,5}csr',
        r'certificatesigningrequest.{0,5}approval',
        r'csr.{0,5}(approve|approval)',
    ],
    'C-0281': [
        r'webhook.{0,5}configuration.{0,5}(access|permission)',
        r'(minimize|restrict).{0,5}webhook.{0,5}config',
    ],
    'C-0282': [
        r'service.{0,5}account.{0,5}token.{0,5}(creat|generat)',
        r'(minimize|restrict).{0,5}token.{0,5}creat',
    ],
 
    # -------------------------------------------------------------------------
    # Network / Ingress / Egress
    # -------------------------------------------------------------------------
    'C-0020': [
        r'mount.{0,5}service.{0,5}principal',
        r'azure.{0,5}service.{0,5}principal',
        r'service.{0,5}principal.{0,5}(mount|secret)',
    ],
    'C-0021': [
        r'exposed?.{0,5}sensitive.{0,5}interface',
        r'sensitive.{0,5}(port|interface|endpoint).{0,5}expos',
        r'(dashboard|api|prometheus|grafana).{0,5}expos',
    ],
    'C-0030': [
        r'ingress.{0,5}(and|&|/).{0,5}egress.{0,5}block',
        r'(block|restrict).{0,5}(ingress|egress)',
        r'network.{0,5}(in|e)gress.{0,5}(block|restrict|deny)',
    ],
    'C-0049': [
        r'network.{0,5}(map|mapping|topology)',
        r'map.{0,5}network',
    ],
    'C-0054': [
        r'cluster.{0,5}internal.{0,5}network',
        r'internal.{0,5}network.{0,5}(segment|isolat)',
        r'pod.{0,5}network.{0,5}internal',
    ],
    'C-0205': [
        r'cni.{0,5}(support|implement).{0,5}network.{0,5}polic',
        r'network.{0,5}polic.{0,5}cni',
        r'calico|cilium|weave|flannel.{0,10}network.{0,5}polic',
    ],
    'C-0206': [
        r'namespace.{0,5}(have|has|missing).{0,5}network.{0,5}polic',
        r'network.{0,5}polic.{0,5}(all|every|each).{0,5}namespace',
        r'(missing|no).{0,5}network.{0,5}polic',
    ],
    'C-0230': [
        r'network.{0,5}polic.{0,5}(enable|set|enforc).{0,5}(gke|google)',
        r'gke.{0,5}network.{0,5}polic',
    ],
    'C-0240': [
        r'network.{0,5}polic.{0,5}(enable|set|enforc).{0,5}(aks|azure)',
        r'aks.{0,5}network.{0,5}polic',
    ],
    'C-0260': [
        r'(missing|no|without).{0,5}network.{0,5}polic',
        r'network.{0,5}polic.{0,5}(missing|absent|not.{0,5}defined)',
    ],
    'C-0263': [
        r'ingress.{0,5}(uses?|with|enable).{0,5}tls',
        r'tls.{0,5}ingress',
        r'ingress.{0,5}(https|ssl|cert)',
    ],
    'C-0266': [
        r'(gateway.{0,5}api|istio).{0,5}(internet|external|ingress)',
        r'istio.{0,5}ingress.{0,5}(expos|internet)',
        r'gateway.{0,5}api.{0,5}(expos|internet)',
    ],
 
    # -------------------------------------------------------------------------
    # Secrets / Encryption
    # -------------------------------------------------------------------------
    'C-0066': [
        r'(secret|etcd).{0,5}encrypt',
        r'encrypt.{0,5}(secret|etcd)',
        r'encryption.{0,5}at.{0,5}rest',
    ],
    'C-0141': [
        r'encryption.?provider.?config',
        r'--encryption-provider-config',
        r'kms.{0,5}(provider|plugin)',
    ],
    'C-0142': [
        r'encryption.{0,5}provider.{0,5}(configured|appropriate)',
        r'(aescbc|aesgcm|secretbox|kms).{0,5}encrypt',
    ],
    'C-0207': [
        r'secret.{0,5}(as|via|using).{0,5}(file|volume)',
        r'prefer.{0,5}secret.{0,5}file',
        r'secret.{0,5}(not|avoid).{0,5}env(ironment)?(.{0,5}var)?',
        r'env.{0,5}secret.{0,5}(avoid|prefer.{0,5}file)',
    ],
    'C-0208': [
        r'external.{0,5}secret.{0,5}(storage|manager|provider)',
        r'(vault|aws.{0,5}secrets?.{0,5}manager|azure.{0,5}keyvault|gcp.{0,5}secret)',
        r'secret.{0,5}(backend|external)',
    ],
    'C-0234': [
        r'external.{0,5}secret.{0,5}(storage|manager).{0,5}(aws|amazon)',
        r'aws.{0,5}(secrets?.{0,5}manager|secret.{0,5}external)',
    ],
    'C-0244': [
        r'kubernetes.{0,5}secret.{0,5}encrypt',
        r'encrypt.{0,5}kubernetes.{0,5}secret',
        r'aks.{0,5}secret.{0,5}encrypt',
    ],
    'C-0255': [
        r'(workload|pod).{0,5}secret.{0,5}access',
        r'secret.{0,5}access.{0,5}(workload|pod)',
    ],
    'C-0259': [
        r'(workload|pod).{0,5}credential.{0,5}access',
        r'credential.{0,5}access.{0,5}(workload|pod)',
    ],
    'C-0264': [
        r'persistent.?volume.{0,5}(without|no|missing).{0,5}encrypt',
        r'(unencrypted|not.{0,5}encrypted).{0,5}persistent.?volume',
        r'pv.{0,5}encrypt',
    ],
 
    # -------------------------------------------------------------------------
    # Admission Controllers
    # -------------------------------------------------------------------------
    'C-0036': [
        r'validat.{0,5}admission.{0,5}(controller|webhook)',
        r'admission.{0,5}webhook.{0,5}validat',
    ],
    'C-0039': [
        r'mutat.{0,5}admission.{0,5}(controller|webhook)',
        r'admission.{0,5}webhook.{0,5}mutat',
    ],
    'C-0068': [
        r'psp.{0,5}(enabled|active)',
        r'pod.{0,5}security.{0,5}polic',
        r'podsecuritypolic',
    ],
    'C-0121': [
        r'EventRateLimit',
        r'event.{0,5}rate.{0,5}limit.{0,5}(admission|plugin)',
        r'admission.{0,5}plugin.{0,5}event.{0,5}rate',
    ],
    'C-0122': [
        r'AlwaysAdmit',
        r'always.{0,5}admit.{0,5}(not.{0,5}set|disable|remove)',
        r'admission.{0,5}always.{0,5}admit',
    ],
    'C-0123': [
        r'AlwaysPullImages',
        r'always.{0,5}pull.{0,5}image',
        r'admission.{0,5}pull.{0,5}image',
    ],
    'C-0124': [
        r'SecurityContextDeny',
        r'security.{0,5}context.{0,5}deny.{0,5}(plugin|admission)',
    ],
    'C-0125': [
        r'ServiceAccount.{0,5}(admission|plugin)',
        r'admission.{0,5}plugin.{0,5}ServiceAccount',
    ],
    'C-0126': [
        r'NamespaceLifecycle',
        r'namespace.{0,5}lifecycle.{0,5}(admission|plugin)',
    ],
    'C-0127': [
        r'NodeRestriction',
        r'node.{0,5}restriction.{0,5}(admission|plugin)',
    ],
    'C-0192': [
        r'(active|enable).{0,5}policy.{0,5}control.{0,5}mechanism',
        r'policy.{0,5}(opa|kyverno|gatekeeper|psp|psa)',
        r'admission.{0,5}policy.{0,5}(active|enforce)',
    ],
    'C-0193': [
        r'(minimize|restrict|prevent).{0,5}admission.{0,5}privileged.{0,5}container',
        r'privileged.{0,5}container.{0,5}(minimize|restrict)',
    ],
    'C-0194': [
        r'(minimize|restrict).{0,5}admission.{0,10}host.?pid',
        r'host.?pid.{0,5}(minimize|restrict)',
    ],
    'C-0195': [
        r'(minimize|restrict).{0,5}admission.{0,10}host.?ipc',
        r'host.?ipc.{0,5}(minimize|restrict)',
    ],
    'C-0196': [
        r'(minimize|restrict).{0,5}admission.{0,10}host.?network',
        r'host.?network.{0,5}(minimize|restrict)',
    ],
    'C-0197': [
        r'(minimize|restrict).{0,5}admission.{0,10}allowPrivilegeEscalation',
        r'allowPrivilegeEscalation.{0,5}(minimize|restrict)',
    ],
    'C-0198': [
        r'(minimize|restrict).{0,5}admission.{0,10}root.{0,5}container',
        r'root.{0,5}container.{0,5}(minimize|restrict|prevent)',
    ],
    'C-0199': [
        r'(minimize|restrict).{0,5}admission.{0,10}net.?raw',
        r'net.?raw.{0,5}capabilit.{0,5}(minimize|restrict)',
    ],
    'C-0200': [
        r'(minimize|restrict).{0,5}admission.{0,10}added.{0,5}capabilit',
        r'added.{0,5}capabilit.{0,5}(minimize|restrict)',
    ],
    'C-0201': [
        r'(minimize|restrict).{0,5}admission.{0,10}capabilit.{0,5}assign',
        r'assign.{0,5}capabilit.{0,5}(minimize|restrict)',
    ],
    'C-0202': [
        r'windows.{0,5}host.?process.{0,5}container',
        r'hostProcess.{0,5}(windows|container)',
    ],
    'C-0203': [
        r'(minimize|restrict).{0,5}admission.{0,10}hostPath.{0,5}volume',
        r'hostPath.{0,5}volume.{0,5}(minimize|restrict)',
    ],
    'C-0204': [
        r'(minimize|restrict).{0,5}admission.{0,10}host.?port',
        r'hostPort.{0,5}(minimize|restrict)',
    ],
    'C-0210': [
        r'seccomp.{0,5}(profile|docker.{0,5}default)',
        r'docker.{0,5}default.{0,5}seccomp',
        r'seccomp.{0,5}pod.{0,5}(definition|spec)',
    ],
    'C-0211': [
        r'security.{0,5}context.{0,5}(pod|container|apply)',
        r'apply.{0,5}security.{0,5}context',
        r'securityContext',
    ],
    'C-0213': [
        r'(minimize|restrict).{0,5}admission.{0,5}privileged.{0,5}(container|gke)',
        r'gke.{0,5}privileged.{0,5}container',
    ],
    'C-0214': [
        r'gke.{0,5}host.?pid',
        r'host.?pid.{0,5}gke',
    ],
    'C-0215': [
        r'gke.{0,5}host.?ipc',
        r'host.?ipc.{0,5}gke',
    ],
    'C-0216': [
        r'gke.{0,5}host.?network',
        r'host.?network.{0,5}gke',
    ],
    'C-0217': [
        r'gke.{0,5}allowPrivilegeEscalation',
        r'allowPrivilegeEscalation.{0,5}gke',
    ],
    'C-0218': [
        r'gke.{0,5}root.{0,5}container',
        r'root.{0,5}container.{0,5}gke',
    ],
    'C-0219': [
        r'gke.{0,5}added.{0,5}capabilit',
        r'added.{0,5}capabilit.{0,5}gke',
    ],
    'C-0220': [
        r'gke.{0,5}capabilit.{0,5}assign',
        r'capabilit.{0,5}assign.{0,5}gke',
    ],
    'C-0275': [
        r'gke2?.{0,10}host.?pid.{0,5}(namespace|minimize)',
        r'host.?pid.{0,10}gke.{0,5}(2|v2)',
    ],
    'C-0276': [
        r'gke2?.{0,10}host.?ipc.{0,5}(namespace|minimize)',
        r'host.?ipc.{0,10}gke.{0,5}(2|v2)',
    ],
 
    # -------------------------------------------------------------------------
    # API Server Configuration
    # -------------------------------------------------------------------------
    'C-0005': [
        r'api.?server.{0,10}insecure.?port',
        r'--insecure-port',
        r'insecure.?port.{0,5}(enabled|set|open)',
    ],
    'C-0113': [
        r'api.?server.{0,10}anonymous.?auth.{0,5}false',
        r'--anonymous-auth.{0,5}(false|disabled)',
    ],
    'C-0114': [
        r'api.?server.{0,10}token.?auth.?file',
        r'--token-auth-file',
        r'static.{0,5}token.{0,5}(file|auth)',
    ],
    'C-0115': [
        r'api.?server.{0,10}DenyServiceExternalIPs.{0,5}not.{0,5}set',
        r'--DenyServiceExternalIPs.{0,5}(not|unset)',
    ],
    'C-0116': [
        r'api.?server.{0,10}kubelet.?client.?(certificate|key)',
        r'--kubelet-client-(certificate|key)',
    ],
    'C-0117': [
        r'api.?server.{0,10}kubelet.?certificate.?authority',
        r'--kubelet-certificate-authority',
    ],
    'C-0118': [
        r'api.?server.{0,10}authorization.?mode.{0,10}(not.{0,5})?AlwaysAllow',
        r'--authorization-mode.{0,10}AlwaysAllow',
    ],
    'C-0119': [
        r'api.?server.{0,10}authorization.?mode.{0,10}Node',
        r'--authorization-mode.{0,10}Node',
    ],
    'C-0120': [
        r'api.?server.{0,10}authorization.?mode.{0,10}RBAC',
        r'--authorization-mode.{0,10}RBAC',
    ],
    'C-0128': [
        r'api.?server.{0,10}secure.?port.{0,10}(not.{0,5})?0',
        r'--secure-port.{0,5}(not.{0,5}0|non.?zero)',
    ],
    'C-0129': [
        r'api.?server.{0,10}profiling.{0,5}false',
        r'--profiling.{0,5}false.{0,10}api.?server',
    ],
    'C-0130': [
        r'api.?server.{0,10}audit.?log.?path',
        r'--audit-log-path',
    ],
    'C-0131': [
        r'api.?server.{0,10}audit.?log.?maxage',
        r'--audit-log-maxage',
    ],
    'C-0132': [
        r'api.?server.{0,10}audit.?log.?maxbackup',
        r'--audit-log-maxbackup',
    ],
    'C-0133': [
        r'api.?server.{0,10}audit.?log.?maxsize',
        r'--audit-log-maxsize',
    ],
    'C-0134': [
        r'api.?server.{0,10}request.?timeout',
        r'--request-timeout',
    ],
    'C-0135': [
        r'api.?server.{0,10}service.?account.?lookup',
        r'--service-account-lookup',
    ],
    'C-0136': [
        r'api.?server.{0,10}service.?account.?key.?file',
        r'--service-account-key-file',
    ],
    'C-0137': [
        r'api.?server.{0,10}etcd.?(cert|key)file',
        r'--etcd-(certfile|keyfile)',
    ],
    'C-0138': [
        r'api.?server.{0,10}tls.?(cert|private.?key).?file',
        r'--tls-(cert|private-key)-file.{0,10}api',
    ],
    'C-0139': [
        r'api.?server.{0,10}client.?ca.?file',
        r'--client-ca-file.{0,10}api',
    ],
    'C-0140': [
        r'api.?server.{0,10}etcd.?cafile',
        r'--etcd-cafile',
    ],
    'C-0143': [
        r'api.?server.{0,10}(strong.{0,5})?cryptograph.{0,5}cipher',
        r'tls.?cipher.{0,5}suit.{0,5}api.?server',
    ],
    'C-0277': [
        r'api.?server.{0,10}(strong.{0,5})?cryptograph.{0,5}cipher.{0,10}gke',
        r'gke.{0,5}api.?server.{0,5}cipher',
    ],
    'C-0283': [
        r'api.?server.{0,10}DenyServiceExternalIPs.{0,5}(set|enabled)',
        r'--DenyServiceExternalIPs.{0,5}(set|enabled)',
    ],
 
    # -------------------------------------------------------------------------
    # Controller Manager
    # -------------------------------------------------------------------------
    'C-0144': [
        r'controller.?manager.{0,10}terminated.?pod.?gc.?threshold',
        r'--terminated-pod-gc-threshold',
    ],
    'C-0145': [
        r'controller.?manager.{0,10}profiling.{0,5}false',
        r'--profiling.{0,5}false.{0,10}controller',
    ],
    'C-0146': [
        r'controller.?manager.{0,10}use.?service.?account.?credentials',
        r'--use-service-account-credentials',
    ],
    'C-0147': [
        r'controller.?manager.{0,10}service.?account.?private.?key.?file',
        r'--service-account-private-key-file',
    ],
    'C-0148': [
        r'controller.?manager.{0,10}root.?ca.?file',
        r'--root-ca-file',
    ],
    'C-0149': [
        r'controller.?manager.{0,10}RotateKubeletServerCertificate',
        r'RotateKubeletServerCertificate.{0,5}controller',
    ],
    'C-0150': [
        r'controller.?manager.{0,10}bind.?address.{0,10}127\.0\.0\.1',
        r'--bind-address.{0,10}127\.0\.0\.1.{0,10}controller',
    ],
 
    # -------------------------------------------------------------------------
    # Scheduler
    # -------------------------------------------------------------------------
    'C-0151': [
        r'scheduler.{0,10}profiling.{0,5}false',
        r'--profiling.{0,5}false.{0,10}scheduler',
    ],
    'C-0152': [
        r'scheduler.{0,10}bind.?address.{0,10}127\.0\.0\.1',
        r'--bind-address.{0,10}127\.0\.0\.1.{0,10}scheduler',
    ],
 
    # -------------------------------------------------------------------------
    # etcd
    # -------------------------------------------------------------------------
    'C-0037': [
        r'coredns.{0,5}poison',
        r'dns.{0,5}poison',
        r'dns.{0,5}spoofing',
    ],
    'C-0153': [
        r'etcd.{0,10}(cert|key).?file',
        r'--cert-file.{0,10}etcd',
        r'--key-file.{0,10}etcd',
    ],
    'C-0154': [
        r'etcd.{0,10}client.?cert.?auth',
        r'--client-cert-auth.{0,10}etcd',
    ],
    'C-0155': [
        r'etcd.{0,10}auto.?tls.{0,5}(not|false)',
        r'--auto-tls.{0,10}etcd',
    ],
    'C-0156': [
        r'etcd.{0,10}peer.?(cert|key).?file',
        r'--peer-(cert|key)-file',
    ],
    'C-0157': [
        r'etcd.{0,10}peer.?client.?cert.?auth',
        r'--peer-client-cert-auth',
    ],
    'C-0158': [
        r'etcd.{0,10}peer.?auto.?tls.{0,5}(not|false)',
        r'--peer-auto-tls',
    ],
    'C-0159': [
        r'etcd.{0,10}unique.{0,5}(certificate.{0,5})?authority',
        r'separate.{0,5}ca.{0,10}etcd',
    ],
 
    # -------------------------------------------------------------------------
    # Kubelet Configuration
    # -------------------------------------------------------------------------
    'C-0069': [
        r'(disable|no).{0,5}anonymous.{0,5}(access|auth).{0,10}kubelet',
        r'kubelet.{0,10}anonymous.{0,5}(access|auth).{0,5}(disable|false)',
    ],
    'C-0070': [
        r'kubelet.{0,10}(client.{0,5})?tls.{0,5}(auth|cert)',
        r'enforce.{0,5}kubelet.{0,5}tls',
    ],
    'C-0162': [
        r'kubelet.{0,5}service.{0,5}file.{0,5}(permission|mode).{0,5}600',
        r'kubelet\.service.{0,5}(chmod|permission)',
    ],
    'C-0163': [
        r'kubelet.{0,5}service.{0,5}file.{0,5}(ownership|owner).{0,5}root',
        r'kubelet\.service.{0,5}(chown|ownership)',
    ],
    'C-0166': [
        r'kubelet\.conf.{0,5}(permission|mode).{0,5}600',
        r'--kubeconfig.{0,5}kubelet\.conf.{0,5}(chmod|permission)',
    ],
    'C-0167': [
        r'kubelet\.conf.{0,5}(ownership|owner).{0,5}root',
        r'--kubeconfig.{0,5}kubelet\.conf.{0,5}(chown|owner)',
    ],
    'C-0170': [
        r'kubelet.{0,5}config\.yaml.{0,5}(permission|mode).{0,5}600',
    ],
    'C-0171': [
        r'kubelet.{0,5}config\.yaml.{0,5}(ownership|owner).{0,5}root',
    ],
    'C-0172': [
        r'kubelet.{0,10}anonymous.?auth.{0,5}false',
        r'--anonymous-auth.{0,5}false.{0,10}kubelet',
    ],
    'C-0173': [
        r'kubelet.{0,10}authorization.?mode.{0,10}(not.{0,5})?AlwaysAllow',
        r'kubelet.{0,10}--authorization-mode.{0,10}AlwaysAllow',
    ],
    'C-0174': [
        r'kubelet.{0,10}client.?ca.?file',
        r'--client-ca-file.{0,10}kubelet',
    ],
    'C-0175': [
        r'kubelet.{0,10}read.?only.?port.{0,10}(0|zero)',
        r'--read-only-port.{0,5}0',
    ],
    'C-0176': [
        r'kubelet.{0,10}streaming.?connection.?idle.?timeout',
        r'--streaming-connection-idle-timeout',
    ],
    'C-0177': [
        r'kubelet.{0,10}protect.?kernel.?defaults',
        r'--protect-kernel-defaults',
    ],
    'C-0178': [
        r'kubelet.{0,10}make.?iptables.?util.?chains',
        r'--make-iptables-util-chains',
    ],
    'C-0179': [
        r'kubelet.{0,10}hostname.?override.{0,5}(not.{0,5}set|unset)',
        r'--hostname-override.{0,10}kubelet',
    ],
    'C-0180': [
        r'kubelet.{0,10}event.?qps',
        r'--event-qps',
    ],
    'C-0181': [
        r'kubelet.{0,10}tls.?(cert|private.?key).?file',
        r'--tls-(cert|private-key)-file.{0,10}kubelet',
    ],
    'C-0182': [
        r'kubelet.{0,10}rotate.?certificates',
        r'--rotate-certificates',
    ],
    'C-0183': [
        r'RotateKubeletServerCertificate.{0,5}(true|enabled)',
        r'kubelet.{0,10}server.{0,5}cert.{0,5}rotat',
    ],
    'C-0184': [
        r'kubelet.{0,10}(strong.{0,5})?cryptograph.{0,5}cipher',
        r'tls.?cipher.{0,5}suit.{0,5}kubelet',
    ],
    'C-0235': [
        r'kubelet.{0,5}config(uration)?.{0,5}(permission|mode).{0,5}644',
        r'kubelet.{0,5}config.{0,5}file.{0,5}(chmod|permission)',
    ],
    'C-0284': [
        r'kubelet.{0,10}(limit|pod).?pid',
        r'--pod-max-pids',
        r'pid.{0,5}limit.{0,10}kubelet',
    ],
 
    # -------------------------------------------------------------------------
    # File Permissions / Ownership
    # -------------------------------------------------------------------------
    'C-0092': [
        r'api.?server.{0,10}(pod.{0,5}spec|manifest).{0,5}(permission|mode).{0,5}600',
        r'kube-apiserver\.yaml.{0,5}(chmod|permission)',
    ],
    'C-0093': [
        r'api.?server.{0,10}(pod.{0,5}spec|manifest).{0,5}(ownership|owner).{0,5}root',
        r'kube-apiserver\.yaml.{0,5}(chown|owner)',
    ],
    'C-0094': [
        r'controller.?manager.{0,10}(pod.{0,5}spec|manifest).{0,5}(permission|mode).{0,5}600',
        r'kube-controller-manager\.yaml.{0,5}(chmod|permission)',
    ],
    'C-0095': [
        r'controller.?manager.{0,10}(pod.{0,5}spec|manifest).{0,5}(ownership|owner).{0,5}root',
        r'kube-controller-manager\.yaml.{0,5}(chown|owner)',
    ],
    'C-0096': [
        r'scheduler.{0,10}(pod.{0,5}spec|manifest).{0,5}(permission|mode).{0,5}600',
        r'kube-scheduler\.yaml.{0,5}(chmod|permission)',
    ],
    'C-0097': [
        r'scheduler.{0,10}(pod.{0,5}spec|manifest).{0,5}(ownership|owner).{0,5}root',
        r'kube-scheduler\.yaml.{0,5}(chown|owner)',
    ],
    'C-0098': [
        r'etcd.{0,10}(pod.{0,5}spec|manifest).{0,5}(permission|mode).{0,5}600',
        r'etcd\.yaml.{0,5}(chmod|permission)',
    ],
    'C-0099': [
        r'etcd.{0,10}(pod.{0,5}spec|manifest).{0,5}(ownership|owner).{0,5}root',
        r'etcd\.yaml.{0,5}(chown|owner)',
    ],
    'C-0100': [
        r'cni.{0,10}(file.{0,5})?(permission|mode).{0,5}600',
        r'container.{0,5}network.{0,5}interface.{0,5}(file.{0,5})?(permission|chmod)',
    ],
    'C-0101': [
        r'cni.{0,10}(file.{0,5})?(ownership|owner).{0,5}root',
        r'container.{0,5}network.{0,5}interface.{0,5}(file.{0,5})?(chown|owner)',
    ],
    'C-0102': [
        r'etcd.{0,10}data.{0,5}dir.{0,5}(permission|mode).{0,5}700',
        r'etcd.{0,5}data.{0,5}(chmod|permission).{0,5}700',
    ],
    'C-0103': [
        r'etcd.{0,10}data.{0,5}dir.{0,5}(ownership|owner).{0,5}etcd',
        r'etcd.{0,5}data.{0,5}(chown|owner).{0,5}etcd',
    ],
    'C-0104': [
        r'admin\.conf.{0,5}(permission|mode).{0,5}600',
        r'admin\.conf.{0,5}(chmod|permission)',
    ],
    'C-0105': [
        r'admin\.conf.{0,5}(ownership|owner).{0,5}root',
        r'admin\.conf.{0,5}(chown|owner)',
    ],
    'C-0106': [
        r'scheduler\.conf.{0,5}(permission|mode).{0,5}600',
        r'scheduler\.conf.{0,5}(chmod|permission)',
    ],
    'C-0107': [
        r'scheduler\.conf.{0,5}(ownership|owner).{0,5}root',
        r'scheduler\.conf.{0,5}(chown|owner)',
    ],
    'C-0108': [
        r'controller.?manager\.conf.{0,5}(permission|mode).{0,5}600',
        r'controller.?manager\.conf.{0,5}(chmod|permission)',
    ],
    'C-0109': [
        r'controller.?manager\.conf.{0,5}(ownership|owner).{0,5}root',
        r'controller.?manager\.conf.{0,5}(chown|owner)',
    ],
    'C-0110': [
        r'pki.{0,10}(dir|directory|file).{0,5}(ownership|owner).{0,5}root',
        r'kubernetes.{0,5}pki.{0,5}(chown|owner)',
    ],
    'C-0111': [
        r'pki.{0,10}cert(ificate)?.{0,5}(permission|mode).{0,5}600',
        r'kubernetes.{0,5}pki.{0,5}(cert|crt).{0,5}(chmod|permission)',
    ],
    'C-0112': [
        r'pki.{0,10}key.{0,5}(permission|mode).{0,5}600',
        r'kubernetes.{0,5}pki.{0,5}key.{0,5}(chmod|permission)',
    ],
    'C-0164': [
        r'proxy.{0,5}kubeconfig.{0,5}(permission|mode).{0,5}600',
        r'proxy.{0,5}kubeconfig.{0,5}(chmod|permission)',
    ],
    'C-0165': [
        r'proxy.{0,5}kubeconfig.{0,5}(ownership|owner).{0,5}root',
        r'proxy.{0,5}kubeconfig.{0,5}(chown|owner)',
    ],
    'C-0168': [
        r'ca.{0,5}(cert|crt|certificate).{0,5}(permission|mode).{0,5}600',
        r'certificate.{0,5}authorit.{0,5}(file.{0,5})?(permission|chmod)',
    ],
    'C-0169': [
        r'(client.{0,5})?ca.{0,5}(cert|crt|certificate).{0,5}(ownership|owner).{0,5}root',
        r'certificate.{0,5}authorit.{0,5}(file.{0,5})?(chown|owner)',
    ],
    'C-0238': [
        r'kubeconfig.{0,5}(permission|mode).{0,5}644',
        r'kubeconfig.{0,5}(chmod|permission).{0,5}644',
    ],
 
    # -------------------------------------------------------------------------
    # Audit / Logging
    # -------------------------------------------------------------------------
    'C-0067': [
        r'audit.{0,5}log.{0,5}(enabled|active|configured)',
        r'(enable|configure).{0,5}audit.{0,5}log',
        r'--audit-log',
    ],
    'C-0160': [
        r'(minimal|minimum|basic).{0,5}audit.{0,5}polic',
        r'audit.{0,5}polic.{0,5}(creat|exist|configur)',
    ],
    'C-0161': [
        r'audit.{0,5}polic.{0,5}(cover|include).{0,5}(key|security|concern)',
        r'comprehensive.{0,5}audit.{0,5}polic',
    ],
    'C-0254': [
        r'(enable|configure).{0,5}audit.{0,5}log',
        r'audit.{0,5}(log|trail|event).{0,5}(enable|active)',
    ],
 
    # -------------------------------------------------------------------------
    # CVEs
    # -------------------------------------------------------------------------
    'C-0058': [
        r'CVE.?2021.?25741',
        r'symlink.{0,10}(arbitrary|host).{0,5}file.{0,5}(system|access)',
    ],
    'C-0059': [
        r'CVE.?2021.?25742',
        r'nginx.{0,5}ingress.{0,5}snippet.{0,5}annotation',
    ],
    'C-0079': [
        r'CVE.?2022.?0185',
        r'linux.{0,5}kernel.{0,5}container.{0,5}escape',
    ],
    'C-0081': [
        r'CVE.?2022.?24348',
        r'argocd.{0,5}dir.{0,5}traversal',
    ],
    'C-0083': [
        r'(workload|pod).{0,10}critical.{0,5}vulnerabilit.{0,10}external.{0,5}traffic',
        r'critical.{0,5}vuln.{0,10}internet.{0,5}(facing|exposed)',
    ],
    'C-0084': [
        r'(workload|pod).{0,10}rce.{0,10}external.{0,5}traffic',
        r'remote.{0,5}code.{0,5}execution.{0,10}external',
    ],
    'C-0085': [
        r'(workload|pod).{0,10}excessive.{0,5}vulnerabilit',
        r'too.{0,5}many.{0,5}vulnerabilit',
    ],
    'C-0087': [
        r'CVE.?2022.?23648',
        r'containerd.{0,5}(fs|filesystem).{0,5}escape',
    ],
    'C-0089': [
        r'CVE.?2022.?3172',
        r'aggregated?.{0,5}api.{0,5}server.{0,5}redirect',
    ],
    'C-0090': [
        r'CVE.?2022.?39328',
        r'grafana.{0,5}auth.{0,5}bypass',
    ],
    'C-0091': [
        r'CVE.?2022.?47633',
        r'kyverno.{0,5}signature.{0,5}bypass',
    ],
 
    # -------------------------------------------------------------------------
    # Image / Registry
    # -------------------------------------------------------------------------
    'C-0221': [
        r'(image|container).{0,5}vulnerabilit.{0,5}scan.{0,10}(ecr|amazon)',
        r'ecr.{0,5}(image|scan)',
        r'amazon.{0,5}(ecr|container.{0,5}registr).{0,5}scan',
    ],
    'C-0222': [
        r'(minimize|restrict).{0,5}user.{0,5}access.{0,10}(amazon.{0,5})?ecr',
        r'ecr.{0,5}user.{0,5}(access|permission)',
    ],
    'C-0223': [
        r'(minimize|restrict).{0,5}cluster.{0,5}access.{0,10}(amazon.{0,5})?ecr',
        r'ecr.{0,5}(read.?only|cluster.{0,5}access)',
    ],
    'C-0236': [
        r'verify.{0,5}image.{0,5}signature',
        r'image.{0,5}signature.{0,5}verif',
        r'(cosign|notation|sigstore)',
    ],
    'C-0237': [
        r'(check|exist).{0,10}signature',
        r'signature.{0,5}(check|exist|present)',
    ],
    'C-0243': [
        r'(image|container).{0,5}vulnerabilit.{0,5}scan.{0,10}(azure|defender)',
        r'azure.{0,5}defender.{0,5}(image|scan)',
    ],
    'C-0250': [
        r'(minimize|restrict).{0,5}cluster.{0,5}access.{0,10}(azure.{0,5})?acr',
        r'acr.{0,5}(read.?only|cluster.{0,5}access)',
    ],
    'C-0251': [
        r'(minimize|restrict).{0,5}user.{0,5}access.{0,10}(azure.{0,5})?acr',
        r'acr.{0,5}user.{0,5}(access|permission)',
    ],
    'C-0253': [
        r'deprecated.{0,5}(kubernetes|k8s).{0,5}image.{0,5}registr',
        r'k8s\.gcr\.io',
        r'registry\.k8s\.io',
    ],
 
    # -------------------------------------------------------------------------
    # Cloud Provider Specific (EKS / GKE / AKS)
    # -------------------------------------------------------------------------
    'C-0225': [
        r'(dedicated|separate).{0,5}(eks|amazon).{0,5}service.{0,5}account',
        r'eks.{0,5}service.{0,5}account',
        r'irsa',
    ],
    'C-0226': [
        r'container.?optimized.{0,5}os',
        r'cos.{0,5}(image|node)',
        r'(gke|google).{0,5}container.{0,5}os',
    ],
    'C-0227': [
        r'(restrict|limit).{0,5}access.{0,10}control.{0,5}plane.{0,5}endpoint',
        r'control.{0,5}plane.{0,5}(public|endpoint).{0,5}(restrict|limit)',
        r'api.{0,5}server.{0,5}(public.{0,5}access|endpoint).{0,5}restrict',
    ],
    'C-0228': [
        r'(private|internal).{0,5}endpoint.{0,5}(enabled|active)',
        r'public.{0,5}(access|endpoint).{0,5}disabled',
        r'cluster.{0,5}(private|internal).{0,5}endpoint',
    ],
    'C-0229': [
        r'(cluster|node).{0,5}private.{0,5}node',
        r'private.{0,5}(worker|node).{0,5}(eks|gke)',
    ],
    'C-0231': [
        r'(encrypt|https|tls).{0,5}(load.{0,5}balancer|alb|elb)',
        r'load.{0,5}balancer.{0,5}tls.{0,5}cert',
    ],
    'C-0232': [
        r'aws.{0,5}iam.{0,5}authenticat',
        r'rbac.{0,5}(aws|iam).{0,5}user',
        r'aws.{0,5}cli.{0,5}(v1\.16|upgrade)',
    ],
    'C-0233': [
        r'fargate.{0,5}(untrusted|workload)',
        r'(untrusted|hostile).{0,5}workload.{0,10}fargate',
    ],
    'C-0239': [
        r'(dedicated|separate).{0,5}aks.{0,5}service.{0,5}account',
        r'aks.{0,5}service.{0,5}account',
    ],
    'C-0241': [
        r'azure.{0,5}rbac.{0,10}kubernetes.{0,5}authoriz',
        r'aks.{0,5}azure.{0,5}rbac',
    ],
    'C-0242': [
        r'hostile.{0,5}multi.?tenant',
        r'multi.?tenant.{0,5}(hostile|untrusted|isolat)',
    ],
    'C-0245': [
        r'(encrypt|https|tls).{0,5}(load.{0,5}balancer).{0,10}(aks|azure)',
        r'aks.{0,5}load.{0,5}balancer.{0,5}tls',
    ],
    'C-0247': [
        r'(restrict|limit).{0,5}access.{0,10}control.{0,5}plane.{0,10}(aks|azure)',
        r'aks.{0,5}control.{0,5}plane.{0,5}endpoint',
    ],
    'C-0248': [
        r'private.{0,5}node.{0,10}(aks|azure)',
        r'aks.{0,5}private.{0,5}(worker|node)',
    ],
    'C-0252': [
        r'(private|internal).{0,5}endpoint.{0,10}(aks|azure)',
        r'aks.{0,5}(private.{0,5}endpoint|public.{0,5}access.{0,5}disabled)',
    ],
    'C-0273': [
        r'outdated.{0,5}kubernetes.{0,5}version',
        r'kubernetes.{0,5}version.{0,5}(old|outdated|deprecated|unsupported)',
        r'(update|upgrade).{0,5}kubernetes.{0,5}version',
    ],
 
    # -------------------------------------------------------------------------
    # Miscellaneous
    # -------------------------------------------------------------------------
    'C-0049': [
        r'network.{0,5}(map|mapping|topology)',
        r'network.{0,5}(discover|visualiz)',
    ],
    'C-0054': [
        r'cluster.{0,5}internal.{0,5}network',
        r'internal.{0,5}network.{0,5}(segmentat|isolat)',
    ],
    'C-0209': [
        r'(admin|management).{0,5}boundar.{0,10}namespace',
        r'namespace.{0,5}(isolat|boundar|segment)',
        r'(resource|workload).{0,5}namespace.{0,5}(separati|boundar)',
    ],
    'C-0253': [
        r'deprecated.{0,5}(k8s|kubernetes).{0,5}(image.{0,5})?registr',
        r'k8s\.gcr\.io',
    ],
    'C-0256': [
        r'external.{0,5}facing.{0,5}(workload|service|pod)',
        r'(workload|pod).{0,5}(internet|external|public).{0,5}(exposed|facing)',
    ],
    'C-0257': [
        r'(workload|pod).{0,5}pvc.{0,5}access',
        r'persistent.{0,5}volume.{0,5}claim.{0,5}access.{0,5}(workload|pod)',
    ],
    'C-0258': [
        r'(workload|pod).{0,5}configmap.{0,5}access',
        r'configmap.{0,5}access.{0,5}(workload|pod)',
    ],
    'C-0261': [
        r'service.{0,5}account.{0,5}token.{0,5}(mounted|auto)',
        r'(mounted|auto.{0,5}mount).{0,5}service.{0,5}account.{0,5}token',
    ],
    'C-0268': [
        r'cpu.{0,5}request.{0,5}(set|configur|missing)',
        r'(missing|no).{0,5}cpu.{0,5}request',
        r'ensure.{0,5}cpu.{0,5}request',
    ],
    'C-0269': [
        r'memory.{0,5}request.{0,5}(set|configur|missing)',
        r'(missing|no).{0,5}memory.{0,5}request',
        r'ensure.{0,5}memory.{0,5}request',
    ],
    'C-0270': [
        r'cpu.{0,5}limit.{0,5}(set|configur|missing)',
        r'(missing|no).{0,5}cpu.{0,5}limit',
        r'ensure.{0,5}cpu.{0,5}limit',
    ],
    'C-0271': [
        r'memory.{0,5}limit.{0,5}(set|configur|missing)',
        r'(missing|no).{0,5}memory.{0,5}limit',
        r'ensure.{0,5}memory.{0,5}limit',
    ],
    'C-0274': [
        r'(verify|authenticate).{0,5}(service|backend)',
        r'mutual.{0,5}tls',
        r'mtls',
        r'service.{0,5}(authenticat|verif)',
    ],
}

def run_kubescape(controls_list, input_path):
    base_cmd = ["kubescape", "scan"]
    if controls_list and controls_list[0] != "NO DIFFERENCES FOUND":
        base_cmd += ["control", ",".join(controls_list)]
    base_cmd += [input_path, "--format", "json"]
    result = subprocess.run(base_cmd, capture_output=True, text=True)
    return result.stdout

def map_difference_to_kubescape_control(difference):
    """
    Pattern matches difference strings to Kubescape control IDs.
    Update the patterns and IDs as needed for your use case.
    """
    # Example pattern-to-control-ID mapping (expand as needed)
    diff_lower = difference.lower()
    for cid, patterns in CONTROL_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, diff_lower, re.IGNORECASE):
                return cid
    return None

def kubescape_json_to_df(json_str, input_path):
    data = json.loads(json_str)

    # Adjust the path below based on actual Kubescape JSON structure
    results = []
    controls = data["summaryDetails"]["controls"]
    # breakpoint()
    for cid, control in controls.items():
        rc = control["ResourceCounters"]
    
        total_resources = (
            rc["passedResources"] +
            rc["failedResources"] +
            rc["skippedResources"] +
            rc["excludedResources"]
        )
        results.append({
            "FilePath": input_path,
            "Severity": control["severity"],
            "Control name": control["name"],
            "Failed resources": rc["failedResources"],
            "All Resources": total_resources,
            "Compliance score": control["complianceScore"],
        })

    df = pd.DataFrame(results)
    return df

def analyze_and_map_differences(name_diff, req_diff, output_path='kubescape_controls.txt'):
    """
    Determines if there are differences and maps them to Kubescape controls.
    Writes result to output_path.
    Returns list of controls or ['NO DIFFERENCES FOUND']
    """
    

    # Simple check: if both files have no difference lines, report no differences
    diff_lines = []
    for line in name_diff.splitlines() + req_diff.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('=') \
            and not line.startswith('Format:') and 'ABSENT' in line \
                and not line.startswith('Present in'):
            diff_lines.append(line)

    if not diff_lines:
        with open(output_path, 'w', encoding='utf-8') as out:
            out.write('NO DIFFERENCES FOUND')
        return ['NO DIFFERENCES FOUND']

    # Map differences to Kubescape controls
    controls = set()
    for line in diff_lines:
        control = map_difference_to_kubescape_control(line)
        if control:
            controls.add(control)

    if not controls:
        # If no controls matched, still report differences generically
        with open(output_path, 'w', encoding='utf-8') as out:
            out.write('NO DIFFERENCES FOUND')
        return ['NO DIFFERENCES FOUND']

    with open(output_path, 'w', encoding='utf-8') as out:
        for ctrl in sorted(controls):
            out.write(ctrl + '\n')
    return list(sorted(controls))

def read_task2_txt_files(file1_path, file2_path):
    """
    Reads and returns the contents of two Task-2 TXT files.
    Args:
        file1_path (str): Path to the first TXT file.
        file2_path (str): Path to the second TXT file.
    Returns:
        tuple: (content1, content2) as strings.
    """
    with open(file1_path, 'r', encoding='utf-8') as f1:
        content1 = f1.read()
    with open(file2_path, 'r', encoding='utf-8') as f2:
        content2 = f2.read()
    return content1, content2

def export_df_to_csv(df, filename="kubescape_results.csv"):
    """
    Exports the given DataFrame to a CSV file.
    """
    df.to_csv(filename, index=False)

if __name__ == "__main__":
    # Txt paths currently hardcoded to match test Task2 output
    file1 = 'name_differences.txt'
    file2 = 'requirement_differences.txt'
    content1, content2 = read_task2_txt_files(file1, file2)
    controls = analyze_and_map_differences(content1, content2)
    kubescape_output = run_kubescape(controls, "project-yamls")
    
    # The dataframe may miss some of the control IDs from kubescape_controls.txt
    # this if because the kubescape output only includes controls that ran and 
    # produced results. "project-yamls" used as the FilePath for the csv
    df = kubescape_json_to_df(kubescape_output, "project-yamls")
    export_df_to_csv(df)